"""Predict PHISHING / UNCERTAIN / LIKELY_SAFE for one URL or many.

    python -m src.inference.predict "https://example.com/login" "https://bit.ly/abc"
    python -m src.inference.predict example.com --domain
    python -m src.inference.predict URL --json

Usable without any web framework (the API in Phase 6 will call this). Steps:
  1. normalize every input (an invalid one gets an error result, the rest go on)
  2. de-duplicate: each distinct URL is scored once per call
  3. look up the model answer in the cache (key: exact URL + model version)
  4. score the misses in batches with the bundled model (no network involved)
  5. look the URL up in the local threat-intelligence database
  6. combine everything with src.inference.decision_engine
The online Google check is not called here yet; it will run in the background
(Phase 4, step 2) so that no answer waits for the network.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Sequence

from src.intelligence.cache import CachePolicies, ResultCache
from src.intelligence.local_database import ThreatIntelConfig, ThreatIntelDB
from src.intelligence.results import IntelResult
from src.preprocessing.url_normalizer import (InvalidURLError, NormalizedURL, normalize_url,
                                              private_registered_domain)

from .bundle import MODELS_DIR
from .decision_engine import Decision, decide
from .runtime import DEFAULT_BATCH_SIZE, ModelRuntime

LOCAL_FEEDS = "local_feeds"
INPUT_TYPES = ("full_url", "domain")


@dataclass(frozen=True)
class PredictionResult:
    url: str                           # the input as given
    input_type: str
    decision: str | None               # None only when the input was invalid
    risk_score: float | None
    source: str | None
    reasons: tuple[str, ...]
    threat_types: tuple[str, ...]
    attributions: tuple[str, ...]
    threat_intel: tuple[dict, ...]
    model_version: str | None
    cache_hit: bool
    error: str | None = None

    def to_dict(self) -> dict:
        out = asdict(self)
        for k in ("reasons", "threat_types", "attributions", "threat_intel"):
            out[k] = list(out[k])
        return out


def is_redirector(n: NormalizedURL, redirectors: set[str]) -> bool:
    site = "" if n.is_ip else private_registered_domain(n.host)
    return bool({n.host, n.registered_domain, site} & redirectors)


class Predictor:
    """Thread-safe if its parts are (they are: runtime, cache and database all lock)."""

    def __init__(self, runtime: ModelRuntime | None, *, threat_db: ThreatIntelDB | None = None,
                 cache: ResultCache | None = None, redirectors: set[str] | None = None):
        self.runtime, self.threat_db, self.cache = runtime, threat_db, cache
        if redirectors is None:
            redirectors = runtime.bundle.redirectors() if runtime is not None else set()
        self.redirectors = redirectors

    @classmethod
    def from_files(cls, bundle_dir: Path | str = MODELS_DIR / "full_url", *,
                   intel_config: Path | str = Path("config/threat_intel.json"),
                   cache_config: Path | str = Path("config/cache.json"), device: str = "cpu",
                   batch_size: int = DEFAULT_BATCH_SIZE) -> "Predictor":
        runtime = ModelRuntime(bundle_dir, device=device, batch_size=batch_size)
        return cls(runtime, threat_db=ThreatIntelDB.from_config(ThreatIntelConfig.from_file(intel_config)),
                   cache=ResultCache(CachePolicies.from_file(cache_config)))

    @property
    def model_version(self) -> str | None:
        return None if self.runtime is None else self.runtime.model_version

    def predict_one(self, value: str, input_type: str = "full_url") -> PredictionResult:
        return self.predict([value], input_type)[0]

    def predict(self, values: Sequence[str], input_type: str = "full_url") -> list[PredictionResult]:
        if isinstance(values, (str, bytes)):
            raise TypeError("predict() expects a list of URLs; use predict_one() for one URL")
        if input_type not in INPUT_TYPES:
            raise ValueError(f"input_type must be one of {INPUT_TYPES}")
        results: list[PredictionResult | None] = [None] * len(values)
        groups: dict[str, list[int]] = {}
        uniques: dict[str, NormalizedURL] = {}
        for i, value in enumerate(values):
            try:
                n = normalize_url(value, input_type)
            except InvalidURLError as exc:
                results[i] = PredictionResult(value if isinstance(value, str) else repr(value),
                                              input_type, None, None, None, (), (), (), (), None,
                                              False, f"invalid_input:{exc.reason}")
                continue
            groups.setdefault(n.canonical, []).append(i)
            uniques.setdefault(n.canonical, n)

        scores, note = self._model_scores(uniques, input_type)
        for key, n in uniques.items():
            intel: dict[str, IntelResult] = {}
            if self.threat_db is not None:
                intel[LOCAL_FEEDS] = self.threat_db.lookup(n)
            p, outcome, hit = scores.get(key, (None, None, False))
            d = decide(input_type=input_type, model_probability=p, model_outcome=outcome,
                       intel=intel, is_redirector=is_redirector(n, self.redirectors),
                       model_note=note)
            for i in groups[key]:
                results[i] = self._result(values[i], input_type, d, p is not None, hit)
        return results

    # ------------------------------------------------------------------ internals
    def _model_scores(self, uniques: dict[str, NormalizedURL], input_type: str):
        scores: dict[str, tuple[float, str, bool]] = {}
        if self.runtime is None or self.runtime.mode != input_type:
            return scores, ""
        version, need = self.runtime.model_version, []
        for key, n in uniques.items():
            if is_redirector(n, self.redirectors):
                continue                                  # decided by rule; model not trusted here
            cached = self.cache.get_prediction(n, version) if self.cache is not None else None
            if cached is not None:
                scores[key] = (cached[0], cached[1], True)
            else:
                need.append(key)
        if need:
            try:
                s = self.runtime.score([uniques[k] for k in need])
            except Exception as exc:                      # keep answering: rules + threat intel
                return scores, f"model error ({type(exc).__name__})"
            for key, p, outcome in zip(need, s.probability, s.outcome):
                scores[key] = (float(p), str(outcome), False)
                if self.cache is not None:
                    self.cache.put_prediction(uniques[key], version, str(outcome), (float(p), str(outcome)))
        return scores, ""

    def _result(self, value: str, input_type: str, d: Decision, model_ran: bool,
                cache_hit: bool) -> PredictionResult:
        intel = tuple({"source": m.source, "level": m.level, "threat_types": list(m.threat_types),
                       "count": m.count, "last_seen": m.last_seen, "expires_at": m.expires_at}
                      for m in d.matches)
        return PredictionResult(value, input_type, d.decision, d.risk_score, d.source, d.reasons,
                                d.threat_types, d.attributions, intel,
                                self.model_version if model_ran else None, cache_hit)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("values", nargs="+", help="URLs (or hostnames with --domain)")
    ap.add_argument("--domain", action="store_true", help="inputs are bare hostnames")
    ap.add_argument("--bundle", type=Path, default=MODELS_DIR / "full_url")
    ap.add_argument("--intel-config", type=Path, default=Path("config/threat_intel.json"))
    ap.add_argument("--cache-config", type=Path, default=Path("config/cache.json"))
    ap.add_argument("--json", action="store_true", help="print full JSON results")
    args = ap.parse_args(argv)
    predictor = Predictor.from_files(args.bundle, intel_config=args.intel_config,
                                     cache_config=args.cache_config)
    for r in predictor.predict(args.values, "domain" if args.domain else "full_url"):
        if args.json:
            print(json.dumps(r.to_dict(), indent=2))
            continue
        if r.error:
            print(f"ERROR        {r.url}  ({r.error})")
            continue
        score = "  -  " if r.risk_score is None else f"{r.risk_score:.3f}"
        print(f"{r.decision:<12} {score}  {r.url}")
        for reason in r.reasons:
            print(f"             - {reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

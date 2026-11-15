"""Calibrate a trained CNN run and choose the three-outcome thresholds.

    python -m src.training.calibrate --run artifacts/runs/full_url_hybrid
    python -m src.training.calibrate --run artifacts/runs/full_url_hybrid --with-test

1. Calibration (Platt scaling, Platt's label smoothing): p = sigmoid(a*logit + b),
   fitted on the validation split. Two numbers and monotone, so the ranking
   (PR-AUC, recall at a given FPR) does not change, only the probabilities.
2. Thresholds, also from validation, from two budgets:
     --max-false-alarm  at most this share of SAFE urls may get PHISHING
     --max-missed       at most this share of PHISHING urls may get LIKELY_SAFE
   Everything in between is UNCERTAIN. Both budgets are rates *within* a class,
   so they do not depend on how much phishing the real traffic contains. The
   report also projects what a user sees at 1% / 5% phishing traffic.
3. --with-test applies the frozen calibration + thresholds to the test split.
   Choose the budgets on validation first; open the test split once.

Writes <run>/calibration.json and reports/calibration_<run>.json (aggregates only).
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from scipy.optimize import minimize

from src.models.calibration import (LIKELY_SAFE, OUTCOMES, PHISHING, UNCERTAIN, Calibrator,
                                    classify, sigmoid)
from src.models.char_cnn import load_checkpoint

from .data import CACHE_DIR, SPLITS_DIR, file_sha256, load_split
from .metrics import binary_metrics, expected_calibration_error, slice_metrics
from .train_cnn import REPORTS_DIR, predict_logits, resolve_device, to_tensors

BASE_RATES = (0.01, 0.05)
GRID_FALSE_ALARM = (0.001, 0.005, 0.01)
GRID_MISSED = (0.02, 0.05, 0.10)


def fit_platt(logits, y) -> tuple[float, float]:
    """Fit p = sigmoid(a*logit + b) by maximum likelihood with Platt's smoothed targets."""
    x = np.asarray(logits, dtype=np.float64)
    y = np.asarray(y)
    if x.ndim != 1 or x.shape != y.shape or len(x) == 0:
        raise ValueError("logits and y must be 1-D arrays of the same, non-zero length")
    if not np.isfinite(x).all():
        raise ValueError("logits must be finite")
    n1, n0 = int((y == 1).sum()), int((y == 0).sum())
    if n1 == 0 or n0 == 0 or n1 + n0 != len(y):
        raise ValueError("calibration needs y in {0,1} with both classes present")
    # Platt (1999): smoothed targets keep the fit finite even if the classes separate.
    t = np.where(y == 1, (n1 + 1) / (n1 + 2), 1 / (n0 + 2))

    def nll(params):
        z = params[0] * x + params[1]
        g = sigmoid(z) - t
        return float(np.mean(np.logaddexp(0.0, z) - t * z)), np.array([np.mean(g * x), np.mean(g)])

    res = minimize(nll, x0=np.array([1.0, 0.0]), jac=True, method="L-BFGS-B")
    a, b = (float(v) for v in res.x)
    if not (np.isfinite(a) and np.isfinite(b)):
        raise RuntimeError("calibration fit diverged")
    if a <= 0:
        raise ValueError("calibration slope is not positive: the model ranks backwards")
    return a, b


def choose_thresholds(p, y, max_false_alarm: float, max_missed: float) -> tuple[float, float]:
    """(t_phishing, t_safe) meeting both budgets on (p, y); t_safe <= t_phishing."""
    if not (0.0 <= max_false_alarm < 1.0 and 0.0 <= max_missed < 1.0):
        raise ValueError("budgets must be in [0, 1)")
    p = np.asarray(p, dtype=np.float64)
    y = np.asarray(y)
    benign = np.sort(p[y == 0])[::-1]          # high -> low
    phish = np.sort(p[y == 1])                 # low -> high
    if len(benign) == 0 or len(phish) == 0:
        raise ValueError("thresholds need both classes")
    k = int(np.floor(max_false_alarm * len(benign)))   # benign allowed above t_phishing
    t_phishing = float(benign[k]) if k < len(benign) else 0.0
    m = int(np.floor(max_missed * len(phish)))         # phishing allowed below t_safe
    t_safe = float(phish[m]) if m < len(phish) else 1.0
    return t_phishing, min(t_safe, t_phishing)


def outcome_report(p, y, t_phishing: float, t_safe: float, base_rates=BASE_RATES) -> dict:
    y = np.asarray(y)
    out = classify(p, t_phishing, t_safe)
    counts, rates = {}, {}
    for cls, lab in (("benign", 0), ("phishing", 1)):
        n = int((y == lab).sum())
        counts[cls] = {o: int(((y == lab) & (out == o)).sum()) for o in OUTCOMES}
        rates[cls] = {o: (c / n if n else None) for o, c in counts[cls].items()}
    fa, caught = rates["benign"][PHISHING], rates["phishing"][PHISHING]
    missed, benign_safe = rates["phishing"][LIKELY_SAFE], rates["benign"][LIKELY_SAFE]
    projected = {}
    for pi in base_rates:
        flagged = pi * caught + (1 - pi) * fa
        called_safe = pi * missed + (1 - pi) * benign_safe
        projected[f"{pi:g}"] = {
            "precision_of_PHISHING": pi * caught / flagged if flagged else None,
            "phishing_among_LIKELY_SAFE": pi * missed / called_safe if called_safe else None,
            "uncertain_share": pi * rates["phishing"][UNCERTAIN] + (1 - pi) * rates["benign"][UNCERTAIN],
        }
    return {"thresholds": {"t_phishing": t_phishing, "t_safe": t_safe},
            "counts": counts, "rates": rates, "false_alarm_rate": fa,
            "phishing_caught_rate": caught, "missed_rate": missed,
            "uncertain_share_in_this_split": float((out == UNCERTAIN).mean()),
            "projected_by_phishing_base_rate": projected}


def threshold_grid(p, y) -> list[dict]:
    rows = []
    for fa in GRID_FALSE_ALARM:
        for mm in GRID_MISSED:
            tp, ts = choose_thresholds(p, y, fa, mm)
            r = outcome_report(p, y, tp, ts)
            rows.append({"max_false_alarm": fa, "max_missed": mm, "t_phishing": tp, "t_safe": ts,
                         "caught": r["phishing_caught_rate"],
                         **{f"{k}@{pi}": v[k] for pi, v in r["projected_by_phishing_base_rate"].items()
                            for k in ("precision_of_PHISHING", "uncertain_share")}})
    return rows


def _calib_quality(y, raw, cal) -> dict:
    return {name: {"ece": expected_calibration_error(y, p), "brier": float(np.mean((p - y) ** 2))}
            for name, p in (("uncalibrated", raw), ("calibrated", cal))}


def calibrate_run(run_dir: Path, *, splits: Path = SPLITS_DIR, with_test: bool = False,
                  max_false_alarm: float = 0.01, max_missed: float = 0.05, device: str = "auto",
                  cache_dir: Path | None = CACHE_DIR, reports_dir: Path = REPORTS_DIR) -> dict:
    run_dir = Path(run_dir)
    ckpt_path = run_dir / "best.pt"
    if not ckpt_path.exists():
        raise FileNotFoundError(f"{ckpt_path} not found: train the run first")
    dev = resolve_device(device)
    model, tokenizer, scaler, meta = load_checkpoint(ckpt_path, map_location=dev)
    model.to(dev)
    mode = meta["mode"]

    val = load_split(mode, "val", splits)
    if val.file_sha256 != meta["data_sha256"]["val"]:
        raise ValueError("the validation split changed since this model was trained")
    val_logits = predict_logits(model, to_tensors(val, tokenizer, scaler, dev, cache_dir))
    a, b = fit_platt(val_logits, val.y)
    val_p = sigmoid(a * val_logits + b)
    t_phishing, t_safe = choose_thresholds(val_p, val.y, max_false_alarm, max_missed)
    cal = Calibrator(a, b, t_phishing, t_safe)

    report = {
        "run": run_dir.name, "mode": mode,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "checkpoint_sha256": file_sha256(ckpt_path),
        "calibrator": cal.to_config(),
        "budgets": {"max_false_alarm": max_false_alarm, "max_missed": max_missed},
        "fitted_on": {"split": "val", "sha256": val.file_sha256, "rows": len(val),
                      "phishing_rate": float(val.y.mean())},
        "val": {"calibration": _calib_quality(val.y, sigmoid(val_logits), val_p),
                "outcomes": outcome_report(val_p, val.y, t_phishing, t_safe)},
        "threshold_grid_val": threshold_grid(val_p, val.y),
        "evaluated_splits": ["val"],
        "note": ("Validation numbers are in-sample for calibration and thresholds; "
                 "the test numbers are the honest estimate."),
    }
    if with_test:
        test = load_split(mode, "test", splits)
        logits = predict_logits(model, to_tensors(test, tokenizer, scaler, dev, cache_dir))
        p = cal.probability(logits)
        report["test"] = {"metrics": binary_metrics(test.y, p),
                          "slices": slice_metrics(test.y, p, test.slices()),
                          "calibration": _calib_quality(test.y, sigmoid(logits), p),
                          "outcomes": outcome_report(p, test.y, t_phishing, t_safe),
                          "sha256": test.file_sha256}
        report["evaluated_splits"].append("test")

    text = json.dumps(report, indent=2) + "\n"
    (run_dir / "calibration.json").write_text(text, encoding="utf-8")
    Path(reports_dir).mkdir(parents=True, exist_ok=True)
    (Path(reports_dir) / f"calibration_{run_dir.name}.json").write_text(text, encoding="utf-8")
    return report


# --------------------------------------------------------------------- printing
def _pct(v) -> str:
    return "-" if v is None else f"{100 * v:.2f}%"


def print_report(r: dict) -> None:
    c = r["calibrator"]
    print(f"run {r['run']} ({r['mode']}): p = sigmoid({c['a']:.4f} * logit + {c['b']:+.4f})")
    q = r["val"]["calibration"]
    print(f"  val ECE {q['uncalibrated']['ece']:.4f} -> {q['calibrated']['ece']:.4f}, "
          f"Brier {q['uncalibrated']['brier']:.4f} -> {q['calibrated']['brier']:.4f}")
    print(f"  budgets: false alarm <= {_pct(r['budgets']['max_false_alarm'])}, "
          f"missed <= {_pct(r['budgets']['max_missed'])}  ->  "
          f"PHISHING if p > {c['t_phishing']:.4f}, LIKELY_SAFE if p < {c['t_safe']:.4f}")
    for split in r["evaluated_splits"]:
        o = r[split]["outcomes"]
        print(f"  [{split}] safe URLs:     PHISHING {_pct(o['rates']['benign'][PHISHING])}  "
              f"UNCERTAIN {_pct(o['rates']['benign'][UNCERTAIN])}  "
              f"LIKELY_SAFE {_pct(o['rates']['benign'][LIKELY_SAFE])}")
        print(f"  [{split}] phishing URLs: PHISHING {_pct(o['rates']['phishing'][PHISHING])}  "
              f"UNCERTAIN {_pct(o['rates']['phishing'][UNCERTAIN])}  "
              f"LIKELY_SAFE {_pct(o['rates']['phishing'][LIKELY_SAFE])}")
        for pi, v in o["projected_by_phishing_base_rate"].items():
            print(f"  [{split}] if {_pct(float(pi))} of traffic is phishing: a PHISHING verdict is "
                  f"right {_pct(v['precision_of_PHISHING'])} of the time, "
                  f"{_pct(v['uncertain_share'])} of URLs are UNCERTAIN")
        if split == "test":
            m = r["test"]["metrics"]
            print(f"  [test] PR-AUC {m['pr_auc']:.4f}, recall@1%FPR "
                  f"{m['recall_at_fpr']['0.01']['recall']:.4f}, ECE {m['ece']:.4f}")
    print("  threshold options (validation):")
    print("    false-alarm  missed  caught   right@5%  uncertain@5%  right@1%  uncertain@1%")
    for g in r["threshold_grid_val"]:
        print(f"    {_pct(g['max_false_alarm']):>11}  {_pct(g['max_missed']):>6}  {_pct(g['caught']):>6}  "
              f"{_pct(g['precision_of_PHISHING@0.05']):>8}  {_pct(g['uncertain_share@0.05']):>12}  "
              f"{_pct(g['precision_of_PHISHING@0.01']):>8}  {_pct(g['uncertain_share@0.01']):>12}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", type=Path, required=True, help="run directory containing best.pt")
    ap.add_argument("--max-false-alarm", type=float, default=0.01)
    ap.add_argument("--max-missed", type=float, default=0.05)
    ap.add_argument("--splits", type=Path, default=SPLITS_DIR)
    ap.add_argument("--device", choices=("auto", "cpu", "cuda"), default="auto")
    ap.add_argument("--with-test", action="store_true", help="score the test split (once!)")
    args = ap.parse_args(argv)
    report = calibrate_run(args.run, splits=args.splits, with_test=args.with_test,
                           max_false_alarm=args.max_false_alarm, max_missed=args.max_missed,
                           device=args.device, cache_dir=CACHE_DIR, reports_dir=REPORTS_DIR)
    print_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

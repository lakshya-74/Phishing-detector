"""Print one comparison table of all CNN runs and the baselines (validation split).

    python -m src.training.summarize
    python -m src.training.summarize --mode domain

Reads artifacts/runs/*/report.json and reports/baselines_<mode>.json. Output is
aggregate numbers only, so it is safe to paste anywhere.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .train_cnn import REPORTS_DIR, RUNS_DIR

SLICES = {"full_url": ("homepage_only", "with_path_or_query", "www_host"),
          "domain": ("with_subdomain", "bare_domain")}


def _row(name: str, epoch, val: dict, mode: str) -> list[str]:
    o = val["overall"]
    r = o.get("recall_at_fpr", {})
    fmt = lambda v: "-" if v is None else f"{v:.4f}"
    cells = [name, "-" if epoch is None else str(epoch), fmt(o.get("pr_auc")),
             fmt(r.get("0.01", {}).get("recall")), fmt(r.get("0.001", {}).get("recall")),
             fmt(o.get("ece"))]
    cells += [fmt(val["slices"].get(s, {}).get("pr_auc")) for s in SLICES[mode]]
    return cells


def summarize(mode: str, runs_dir: Path = RUNS_DIR, reports_dir: Path = REPORTS_DIR) -> list[list[str]]:
    rows = []
    base = reports_dir / f"baselines_{mode}.json"
    if base.exists():
        rep = json.loads(base.read_text(encoding="utf-8"))
        for name, res in rep["models"].items():
            rows.append(_row(f"baseline:{name}", None, res["val"], mode))
    for path in sorted(Path(runs_dir).glob("*/report.json")):
        rep = json.loads(path.read_text(encoding="utf-8"))
        if rep.get("mode") == mode:
            label = f"{path.parent.name} ({rep['model']}, seed {rep['config']['seed']})"
            rows.append(_row(label, rep.get("best_epoch"), rep["results"]["val"], mode))
    return rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=tuple(SLICES), default="full_url")
    ap.add_argument("--runs", type=Path, default=RUNS_DIR)
    ap.add_argument("--reports", type=Path, default=REPORTS_DIR)
    args = ap.parse_args(argv)
    head = ["model", "best_ep", "PR-AUC", "rec@1%FPR", "rec@0.1%FPR", "ECE",
            *[f"PR-AUC[{s}]" for s in SLICES[args.mode]]]
    rows = [head] + summarize(args.mode, args.runs, args.reports)
    widths = [max(len(r[i]) for r in rows) for i in range(len(head))]
    print(f"validation split, mode={args.mode}")
    for r in rows:
        print("  ".join(c.ljust(w) for c, w in zip(r, widths)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

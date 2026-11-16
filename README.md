# Phishing Detector

A Python project workspace for building and testing phishing URL detection tools.

## Current status

Phishing-detection module of the Bharat AI on-device security assistant.

| Area | Status |
|---|---|
| URL normalizer (`src/preprocessing/url_normalizer.py`) | done, tested |
| Character tokenizer (`src/preprocessing/tokenizer.py`) | done, tested |
| Structural features + scaler (`src/preprocessing/feature_extractor.py`) | done, tested |
| Feed downloader / parsers / dataset builder (`src/data/`) | done, tested |
| Benign full-URL sampler, Common Crawl (`src/data/commoncrawl_sample.py`) | done, tested |
| Cleaning + leakage-safe train/val/test split (`src/data/split_dataset.py`) | done, tested |
| Training data loader, metrics, classic baselines (`src/training/`) | done, tested |
| Char-CNN / hybrid model + resumable trainer (`src/models/`, `src/training/train_cnn.py`) | done, tested, trained on GPU (full_url) |
| Calibration + three-outcome thresholds (`src/training/calibrate.py`) | done, tested; full_url test run done (false-alarm budget not met, see below) |
| Per-website error inspection (`src/training/inspect_errors.py`) | done, tested |
| Threat intelligence, inference engine, API, ARM deployment | not started |

## Requirements

- **64-bit** Python 3.10–3.12 (PyTorch has no 32-bit Windows build)
- Packages listed in `requirements.txt`
- PyTorch, installed separately for your operating system and hardware

## Setup

Create and activate a virtual environment, then install the project dependencies.
If `py --version` reports a 32-bit interpreter, pass a 64-bit one explicitly
(for example `py -3.11 -m venv .venv`).

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Install PyTorch separately using the instructions at
[pytorch.org](https://pytorch.org/get-started/locally/) to select the
appropriate CPU or CUDA build.

## Check your environment

Run the environment check from the repository root:

```powershell
python scripts/check_env.py
```

The script reports the Python version, platform, installed project packages,
PyTorch/CUDA availability, and runs a small PyTorch `Embedding`/`Conv1d` smoke
test. It exits with an error if PyTorch is not installed.

## Data pipeline

Raw data is never committed; every step can be reproduced from these commands.

```powershell
# 1. Phishing feeds (PhishTank keyless, OpenPhish) and the Tranco top-1M list.
#    Run this once a day for a while: each snapshot adds new phishing URLs.
python -m src.data.download_datasets

# 2. Benign FULL URLs from the Common Crawl index (~1 GB of index blocks, one-time).
python -m src.data.commoncrawl_sample

# 3. Merge, normalize and deduplicate everything into data/processed/.
python -m src.data.build_dataset

# 4. Clean and split into leakage-safe train/val/test (data/processed/splits/).
python -m src.data.split_dataset
```

What step 4 does, and why:

- **Two datasets.** `full_url/` (host + path + query) and `domain/` (hostnames
  only, for DNS/SNI traffic) are trained separately, so "no path" can never
  become a shortcut for "benign".
- **Redirector links removed** (URL shorteners and QR-code services from the
  public list plus [config/redirectors_local.txt](config/redirectors_local.txt)).
  Their URL hides the destination; at inference they are reported as UNCERTAIN.
  `split_report.json` lists *candidate* redirectors found by pattern; a human
  reviews them before adding them to the local list.
- **Group split.** Every URL is assigned to train/val/test by its registered
  domain (PSL private suffixes honoured, so `a.web.app` and `b.web.app` are
  different sites), so the test set only contains websites the model never saw.
- **Per-site cap** (50 per split/label/site), so one abused platform cannot
  dominate training.
- **Shortcut monitors** in the report compare the two labels (length, paths,
  subdomains) to reveal remaining shortcuts.
- `--future-cutoff <ISO time>` puts sites first seen after that time in a
  separate `test_future` split for time-based evaluation.

| Source | Label | What it gives | Notes |
|---|---|---|---|
| PhishTank `online-valid` | phishing | full URLs, community-verified | new-user registration is closed, so keyless (a few downloads/day) |
| OpenPhish community feed | phishing | full URLs | non-commercial use only |
| Tranco top-1M | benign (weak) | domain names only | used for domain-only mode and as a popularity filter |
| Tranco homepages | benign (weak) | `https://<domain>/` for 20k sampled domains | balances bare-homepage phishing URLs |
| Common Crawl URL index | benign (weak) | full page URLs on top Tranco domains | only index metadata is read; no page is visited |
| PeterDaveHello/url-shorteners | reference | ~1,450 shortener domains | CC BY-SA 4.0; routing only, never a label |

`data/processed/build_report.json` summarizes counts, duplicates, rejects and
warnings, and contains no raw URLs.

## Baselines

```powershell
python -m src.training.baselines              # validation split only
python -m src.training.baselines --with-test  # final comparison only
```

The test split stays untouched until the final comparison, so it remains an
honest exam on unseen websites. Reports (aggregate numbers only, no URLs) go
to `reports/baselines_<mode>.json`, including per-slice results.

First run, **validation split**, 2026-11-14 (C grid up to 10). "Recall @1% FPR"
is the share of phishing caught while wrongly flagging at most 1 in 100 safe URLs.

| Mode | Model | PR-AUC | ROC-AUC | Recall @1% FPR |
|---|---|---|---|---|
| full_url | shortcut probe (4 length numbers) | 0.611 | 0.756 | 0.359 |
| full_url | structural features + LR | 0.759 | 0.899 | 0.392 |
| full_url | structural features + boosted trees | 0.845 | 0.949 | 0.539 |
| full_url | char 2–5-gram TF-IDF + LR | **0.914** | **0.967** | **0.727** |
| domain | shortcut probe | 0.740 | 0.913 | 0.695 |
| domain | char 2–5-gram TF-IDF + LR | 0.860 | 0.944 | 0.785 |

Known issue: in **domain mode** 84% of hosts with a subdomain are phishing, so
the length-only probe already scores well. On bare domains alone the best
model reaches only PR-AUC 0.30. The domain dataset needs more benign subdomain
hosts before its numbers mean much.

## Training the character CNN

```powershell
python -m src.training.train_cnn                    # full_url, plain char-CNN
python -m src.training.train_cnn --model hybrid     # CNN + structural features
python -m src.training.train_cnn --device cuda      # refuse to fall back to CPU
```

- Model: character embedding → Conv1d (widths 3/5/7) → masked max-pool →
  small MLP (~90k parameters, about 0.4 MB in float32). Padding is masked, so
  the result does not depend on how much padding follows the URL.
- After every epoch the full state goes to `artifacts/runs/<mode>_<model>/last.pt`;
  running the same command again **resumes**. The best epoch (validation
  PR-AUC) is kept in `best.pt`, and training stops after `--patience` epochs
  without improvement.
- Reports: `reports/cnn_<mode>_<model>.json` (aggregates only), which also quote
  the baseline score to beat.

### First GPU results (full_url, validation split, 2026-11-15)

NVIDIA RTX 2000 Ada, about 9 s per epoch, 3 seeds each:

| Model | PR-AUC (3 seeds) | Recall @1% FPR (3 seeds) |
|---|---|---|
| char n-gram LR baseline | 0.9135 | 0.727 |
| char-CNN | 0.918 / 0.921 / 0.923 | 0.745 / 0.726 / 0.756 |
| **hybrid (CNN + features)** | **0.929 / 0.930 / 0.935** | **0.749 / 0.775 / 0.788** |

The hybrid's worst seed beats the CNN's best seed on PR-AUC. Raw neural-net
probabilities are less well calibrated (ECE ~0.03 vs 0.012 for LR), so they
are calibrated before thresholds are set.

### Calibration and the three outcomes

```powershell
python -m src.training.calibrate --run artifacts/runs/full_url_hybrid                # validation
python -m src.training.calibrate --run artifacts/runs/full_url_hybrid --with-test    # once, at the end
python -m src.training.summarize --split test
```

- `p = sigmoid(a·logit + b)` (Platt scaling) is fitted on validation. It is
  monotone, so ranking metrics do not change.
- **PHISHING** if `p > t_phishing`, chosen so at most `--max-false-alarm` of
  safe URLs get it. **LIKELY_SAFE** if `p < t_safe`, chosen so at most
  `--max-missed` of phishing URLs get it. Everything else is **UNCERTAIN**.
- These budgets are rates *within* each class, so they hold whatever the real
  phishing share is. The report also projects how often a PHISHING verdict is
  right when only 1% or 5% of traffic is phishing. With rare phishing, even a
  1% false-alarm rate makes most PHISHING verdicts wrong, so the false-alarm
  budget must be strict.
- Output: `<run>/calibration.json` (the `calibrator` block is what the
  inference engine loads) and `reports/calibration_<run>.json`.

#### Validation results (full_url hybrid, seed 13, 2026-11-15)

`p = sigmoid(0.477·logit − 0.418)`. The slope below 1 means the raw model
was over-confident. ECE 0.028 → 0.004, Brier 0.0375 → 0.0348. Validation has
10,178 safe and 2,160 phishing URLs.

| False-alarm budget | Phishing caught | PHISHING verdict right, 1% / 5% phishing traffic |
|---|---|---|
| 0.1% | 60.0% | 86.0% / 97.0% |
| 0.5% | 73.0% | 60.0% / 88.7% |
| 1.0% | 78.8% | 44.5% / 80.7% |

The missed budget sets the UNCERTAIN share (at 1% phishing traffic):
2% → ~39%, 5% → ~17%, 10% → ~5%.

Recommended: **0.1% false alarm, 5% missed**.

- Phishing is rare in real traffic, so looser budgets make most PHISHING
  verdicts false alarms.
- The benign data comes from popular sites, so real false alarms will likely
  be higher than validation shows.
- Phishing that misses the PHISHING verdict mostly lands in UNCERTAIN (35%),
  not LIKELY_SAFE (5%).

At 0.1% the threshold is set by only about 10 safe validation URLs.

### Final test results (full_url, 2026-11-16)

The test split was opened once, with the models, seeds and budgets fixed
beforehand. The neural models are seed 13 and calibrated. The baselines'
ECE is uncalibrated.

| Model | PR-AUC | Recall @1% FPR | Recall @0.1% FPR | ECE | PR-AUC homepage / path / www |
|---|---|---|---|---|---|
| shortcut probe | 0.649 | 0.355 | 0.013 | 0.028 | 0.908 / 0.274 / 0.394 |
| structural features + LR | 0.771 | 0.518 | 0.064 | 0.015 | 0.934 / 0.583 / 0.358 |
| structural features + boosted trees | 0.858 | 0.541 | 0.146 | 0.019 | 0.959 / 0.724 / 0.680 |
| char 2–5-gram TF-IDF + LR | 0.924 | **0.740** | **0.517** | **0.009** | 0.957 / **0.874** / 0.739 |
| char-CNN | 0.910 | 0.700 | 0.292 | 0.014 | 0.956 / 0.846 / 0.778 |
| hybrid (CNN + features) | **0.929** | 0.716 | 0.319 | 0.013 | **0.972** / 0.860 / **0.870** |

Three outcomes on test with the 0.1% false-alarm / 5% missed budgets:

| Model | Safe → PHISHING (budget 0.1%) | Phishing caught | Phishing → LIKELY_SAFE (budget 5%) | PHISHING right at 1% / 5% phishing traffic |
|---|---|---|---|---|
| hybrid | **0.56%** | 61.5% | 2.2% | 52.8% / 85.4% |
| char-CNN | **0.33%** | 61.1% | 3.0% | 64.9% / 90.6% |

What this shows:

- The hybrid's lead over the n-gram baseline shrank from 0.021 PR-AUC
  (validation) to 0.005 (test), about the size of the seed-to-seed spread.
  Choosing the best seed and epoch on validation probably flattered the
  neural models there.
- At strict false-alarm levels the baseline is clearly better (52% vs 32%
  caught at 0.1% FPR). The hybrid wins on homepage-only and `www.` URLs; the
  baseline wins on URLs with a path.
- The false-alarm budget did **not** hold on test, while the phishing-side
  budget did. Safe URLs come in groups of up to 21 per website and each split
  has only ~2,400 safe websites, so a 0.1% threshold rests on a handful of
  websites.

These numbers stay as reported. Any later model change is judged on
validation and confirmed on fresh data, not on this test split.

### Inspecting mistakes per website

```powershell
python -m src.training.inspect_errors --run artifacts/runs/full_url_hybrid --with-test
```

Counts false alarms and misses per URL **and per website**, with a range from
resampling whole websites. For validation it also lists the safe websites
with the highest scores, showing host and path only (no query strings). For
test it prints counts only. Nothing is written to disk.

### Over SSH on Windows

Windows OpenSSH ends every program from a session when it disconnects. Start
training as a scheduled task instead:

```bat
scripts\train_background.cmd start --model cnn --device cuda
scripts\train_background.cmd status      &rem progress (safe to run any time)
scripts\train_background.cmd stop        &rem stop; "start" again resumes
```

Output is appended to `logs\train.log`.

## Training on a GPU PC (Windows)

1. Clone the repo, create a 64-bit venv, run `pip install -r requirements.txt`,
   then install the CUDA build of PyTorch from pytorch.org.
2. If `import torch` fails with **WinError 126/448**, install the *Microsoft
   Visual C++ 2015–2022 Redistributable (x64)*. **WinError 4551** means an
   Application Control policy is blocking the DLLs; ask the machine's
   administrator for an allow rule.
3. Copy `data/processed/splits/` from the machine that built the dataset
   (data is not in Git), then run `python scripts/check_env.py`.

## Project layout

```text
data/          Local data directories (ignored by Git)
logs/          Local logs (ignored by Git)
models/        Local model files
scripts/       Development and environment-check scripts
src/           Application source package
tests/         Test package
```

## Dependencies

Runtime and development Python dependencies are listed in `requirements.txt`.
PyTorch is intentionally managed separately because the appropriate package
depends on the platform and hardware.

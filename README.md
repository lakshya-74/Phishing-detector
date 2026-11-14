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
| CNN model, training, calibration | not started |
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

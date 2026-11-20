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
| Per-website budgets, n-gram model without pickle, CNN + n-gram combination (`src/training/ensemble.py`) | done, tested; run on GPU: **hybrid + n-gram chosen for full_url** |
| Threat intelligence: local database + matcher (`src/intelligence/`) | done, tested; built from real feeds |
| Threat intelligence: answer cache with separate TTL policies (`src/intelligence/cache.py`) | done, tested |
| Threat intelligence: online lookups, Google Safe Browsing v5 (`src/intelligence/safe_browsing.py`) | done, tested offline; off by default; not yet tried against the real API |
| URLhaus feed | skipped (decided 2026-11-20): malware, not phishing; terms restrict AI products |
| Inference engine, step 1: model bundle, runtime, decision engine, single/batch predict (`src/inference/`) | done, tested; run on the real model |
| Inference engine, step 2: queues, concurrency, background Google lookups, benchmarks | next |
| API, ARM deployment | not started |

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
- **Data feeding:** a PyTorch `Dataset` (`URLDataset`) and `DataLoader`. A
  batch sampler hands over one whole batch per call, and the data stays on the
  GPU. Each epoch uses one shuffle from a seeded generator. The loader has its
  own private generator, so dropout's random numbers are untouched. Training
  is bit-identical to the earlier hand-written loop, which was checked on the
  CNN, the hybrid and the shipped model's predictions.
- **Reports:** accuracy and the confusion matrix `[[tn, fp], [fn, tp]]` are
  included at threshold 0.5, as reference points only. The three-outcome
  version is under `counts` in the calibration and ensemble reports.
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

The results below were produced with per-URL budgets (`--unit url`).
Per-website budgets came later; see the next sections.

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

Findings at the 0.1% budget (2026-11-16):

| Model | Val false alarms | Test false alarms | Test without the worst website |
|---|---|---|---|
| hybrid | 10 URLs from 4 of 2,402 safe websites | 60 URLs from 9 of 2,492 (worst: 20) | 0.37% |
| char-CNN | 10 URLs from 8 of 2,402 | 36 URLs from 4 of 2,492 (worst: 20) | 0.15% |

- **False alarms come in website-sized lumps**, so the per-URL rate jumps
  whenever one flagged website brings 20 URLs.
- **The highest-scoring "safe" websites are genuine.** Examples are webmail,
  extranet and app login pages, status pages with long incident IDs, and a
  Bitcoin explorer's address pages. The labels look right; this is a real
  blind spot of judging from the URL alone.
- **It is not a simple keyword shortcut in training.** Login-type words
  appear in 2.4% of safe and 2.9% of phishing training paths. Long random
  strings are more common in safe paths (39% vs 13%).
- **The two estimates are consistent.** The per-website ranges for
  validation (0.01–0.23%) and test (0.08–1.18%) overlap. A 0.1% budget is
  about 2–3 websites out of ~2,400, which is below what this much data can
  measure.

### Per-website budgets and combining models (validation only)

Calibration now counts **every website once** by default (`--unit website`),
with a 0.5% false-alarm budget. That is about 12 of the ~2,400 safe
validation websites. `--unit url` restores the old per-URL counting.

```powershell
python -m src.training.ensemble --cnn-run artifacts/runs/full_url_hybrid
python -m src.training.ensemble --cnn-run artifacts/runs/full_url_cnn     # reuses the n-gram model
```

`ensemble` compares three candidates on validation: the CNN run alone, the
n-gram model alone, and both combined as
`p = sigmoid(w1·cnn_logit + w2·ngram_logit + b)` with both weights > 0.

- **Never reads the test split.** It was used once, above. A new model is
  judged on validation and confirmed later on fresh data.
- **Honest validation numbers.** They are cross-fitted over websites: weights
  and thresholds are fitted on 4/5 of the validation websites and applied to
  the other 1/5, five times.
- **The n-gram model is the `char_ngram_lr` baseline**, with the same
  settings and C search. It is saved to `artifacts/runs/<mode>_ngram/model.npz`
  as plain arrays and loaded with `allow_pickle=False`, so opening a model
  file cannot run code. It is reused while the data is unchanged.
- **Final calibrators** for all three candidates, fitted on all of
  validation, go to `artifacts/runs/<cnn run>_ensemble/ensemble.json`. A
  report with aggregate numbers only goes to `reports/ensemble_<cnn run>.json`.
- **`calibrate` keeps the exam record.** It refuses to overwrite a
  `calibration.json` that holds test-split results unless you pass `--force`.

### Chosen full_url model (2026-11-16)

Validation numbers, cross-fitted over websites, with budgets of 0.5% false
alarm and 5% missed (every website counts once):

| Candidate | PR-AUC | Phishing caught | Safe websites flagged | PHISHING right @1% phishing | UNCERTAIN @1% |
|---|---|---|---|---|---|
| char n-gram LR | 0.911 | 76.4% | 17 / 2,402 | 60.5% | 27.3% |
| char-CNN | 0.922 | 80.9% | 31 / 2,402 | 59.6% | 34.3% |
| char-CNN + n-gram | 0.930 | 79.1% | 23 / 2,402 | 61.7% | 27.2% |
| hybrid | 0.933 | 83.6% | 29 / 2,402 | 60.0% | 21.5% |
| **hybrid + n-gram** | **0.938** | **83.6%** | 24 / 2,402 | **62.7%** | **18.2%** |

**Decision: hybrid + n-gram**,
`p = sigmoid(0.332·hybrid_logit + 0.391·ngram_logit + 0.037)`.

- **Rule set beforehand:** the combination had to beat the best single model
  by more than 0.005 PR-AUC. It passed narrowly (+0.0053).
- **It also helps elsewhere:** it gives fewer UNCERTAIN verdicts (18% vs 21%)
  and wrongly flags fewer safe websites (24 vs 29), within the 0.5% budget.
- **No test-set number yet.** The combination will get one from the fresh
  exam on new data.
- **What a verdict means in practice:** at 1% phishing traffic a PHISHING
  verdict is right about 63% of the time. The product should present it as
  "high risk, here is why", not as proof.
- **Deviation from the specification (decided 2026-11-18).** The spec says
  "the central detection mechanism must be a trained neural network". In this
  combination the neural hybrid is one of two learned members, each with a
  comparable say. Neither member uses keyword rules. It was kept because
  validation justified it. The hybrid alone (PR-AUC 0.933, 21% UNCERTAIN) is
  the documented fallback.
- **Cost on the device:** it runs the PyTorch hybrid (or its exported form)
  plus the scikit-learn n-gram member.

The shipped model is three files, kept out of Git under `artifacts/`:

- `artifacts/runs/full_url_hybrid/best.pt`
- `artifacts/runs/full_url_ngram/model.npz`
- `artifacts/runs/full_url_hybrid_ensemble/ensemble.json`

`ensemble.json` records each member's SHA-256 hash, so the inference engine
can refuse mismatched files.
- **Caveat:** the CNN's best epoch and the n-gram model's C were both chosen on
  validation, which flatters both members a little.

### Over SSH on Windows

Windows OpenSSH ends every program from a session when it disconnects. Start
training as a scheduled task instead:

```bat
scripts\train_background.cmd start --model cnn --device cuda
scripts\train_background.cmd status      &rem progress (safe to run any time)
scripts\train_background.cmd stop        &rem stop; "start" again resumes
```

Output is appended to `logs\train.log`.

## Threat intelligence (local database)

Known phishing URLs from the feeds in `data/raw/` go into one local SQLite
file, `data/intel/threat_intel.sqlite3` (Git-ignored: the OpenPhish feed is
for non-commercial use only). Settings are in
[config/threat_intel.json](config/threat_intel.json).

```powershell
python -m src.data.download_datasets                     # fresh feed snapshots (daily)
python -m src.intelligence.local_database update         # ingest only snapshots not seen yet
python -m src.intelligence.local_database stats
python -m src.intelligence.local_database lookup "https://example.com/login"
python -m src.intelligence.local_database lookup example.com --domain
```

- **Independent of the model and fully offline.** This module never makes a
  network request and never sends a URL anywhere. Downloading is a separate
  step.
- **Three match levels:**
  - `exact_url`: the same page. The scheme, `#fragment`, host case and
    default port are ignored.
  - `hostname`: another listed page on the same host.
  - `registered_domain`: a listed sibling host, such as `a.evil.xyz` vs
    `b.evil.xyz`.

  The last two apply only when the site is neither in the Tranco top 100k
  nor a URL shortener or QR redirector. PSL private suffixes count as
  separate sites, so `evil.github.io` is not `github.io`.
- **Source attribution:** every match names its feed, the number of listed
  URLs, first and last seen, expiry, and up to three feed IDs.
- **Expiry:** an entry expires 7 days after the newest snapshot that listed
  it. `update` deletes expired entries. Results carry `stale: true` if the
  newest snapshot is more than 48 hours old.
- **`no_match` never means safe.** It only means no feed knows the URL. A
  lookup that cannot run returns `unavailable` and never raises.
- **Speed:** lookups use an in-memory copy of the file, reloaded when the
  file changes. If a new file is damaged, the last good copy stays in use.
  Reading the file directly cost 13 ms per lookup on Windows because of file
  locking; the copy takes 0.22 ms, or 0.08 ms for an already-normalized URL.
  Measured on the development laptop under load, not on the Pi.

First real build (laptop, 2026-11-17; 3 PhishTank + 3 OpenPhish snapshots):

| | |
|---|---|
| Records read | 134,855 PhishTank + 900 OpenPhish (27 invalid URLs skipped) |
| Active entries | 46,579 on 19,757 hosts; file 15.7 MB |
| Host-level matching allowed | 39% of entries |
| Exact-only sites with the most entries | google.com 5,253 · qrco.de 4,586 · q-r.to 3,509 · ead.me 3,290 · bit.ly 1,594 · weebly.com 1,197 · adobe.com 1,113 |

Most phishing in the feeds sits on big abused platforms and QR-code
redirectors. Host-level matching there would flag legitimate services, so
those entries match exact URLs only.

### Answer cache

[src/intelligence/cache.py](src/intelligence/cache.py) stores recent answers
so repeated links cost neither a model run nor an online lookup. Settings are
in [config/cache.json](config/cache.json).

| Kind of answer | Kept for | Why |
|---|---|---|
| Model said PHISHING or UNCERTAIN | 1 hour | |
| Model said LIKELY_SAFE | 15 minutes | a safe page can be turned malicious later |
| Confirmed threat-intel match | 6 hours, never past the source's own expiry | |
| No feed or provider lists it | 15 minutes | |
| An online lookup failed | 60 seconds | retry soon without hammering the service |

- **Keys are the exact normalized URL**, including the scheme. There is no
  host or domain entry, so one safe page never makes its website safe.
- **Prediction keys include the model version**, so a new model never serves
  old answers.
- **Keys are SHA-256 digests**, so the cache holds no readable URLs.
- **Bounded size:** least-recently-used entries are evicted. The cache is
  thread-safe and uses a monotonic clock. Hit rate is reported in `stats()`.

### Online sources: research (2026-11-18)

What the official pages say today:

- **URLhaus (abuse.ch): not integrated.**
  - It lists *malware* URLs, and its own policy says "Phishing is not Malware".
  - Downloads need a free Auth-Key placed in the URL, and dumps must not be
    fetched more often than every 5 minutes.
  - The abuse.ch Terms of Use forbid using the data to "train, or otherwise
    improve any artificial intelligence model or product" without Spamhaus'
    written consent.
  - The CSV columns are only documented behind a login, so they could not be
    verified.

  Sources: [URLhaus API](https://urlhaus.abuse.ch/api/),
  [about](https://urlhaus.abuse.ch/about/),
  [abuse.ch Terms of Use](https://abuse.ch/terms-of-use/),
  [changelog](https://abusech-docs.spamhaus.com/changelog).
- **Google Safe Browsing v5 (`hashes:search`): the candidate.**
  - It sends only 4-byte prefixes of SHA-256 hashes of URL expressions,
    never the URL. It is free, with an API key.
  - Use is **non-commercial only** without a separate agreement.
  - Warnings must say "suspected" or "possible", carry "Advisory provided by
    Google", and state that accuracy cannot be guaranteed.
  - A URL must not be warned about on Google data older than 30 minutes.
  - Positive and negative answers must be cached for the given
    `cacheDuration`.

  Sources: [overview](https://developers.google.com/safe-browsing/reference),
  [hashes.search](https://developers.google.com/safe-browsing/reference/rest/v5/hashes/search),
  [usage limits](https://developers.google.com/safe-browsing/v4/usage-limits),
  [terms](https://developers.google.com/safe-browsing/terms).
- **Google Web Risk**, the commercial version: its Lookup API sends the full
  URL, and its Update API keeps a local database of hashes. Pricing could not
  be read from the page.
  Source: [overview](https://docs.cloud.google.com/web-risk/docs/overview).
- **VirusTotal public API: not used.** It allows 4 requests a minute and 500
  a day, and cannot be used in products or services that earn money.
  Source: [public vs premium API](https://docs.virustotal.com/reference/public-vs-premium-api).

### Online lookups: Google Safe Browsing v5 (optional, off by default)

[src/intelligence/safe_browsing.py](src/intelligence/safe_browsing.py) only
runs when the environment variable `SAFE_BROWSING_API_KEY` is set. Without
it, every check returns `unavailable` / `disabled:no_api_key`, and the rest
of the system is unaffected.

```bat
python -m src.intelligence.safe_browsing expressions "https://a.b.example.com/1/2.html?x=1"
set SAFE_BROWSING_API_KEY=your-key-here
python -m src.intelligence.safe_browsing check "https://example.com/"
```

`expressions` works offline and shows what would be hashed. `set` keeps the
key for this window only; don't use `setx`, which stores it permanently.

- **What leaves the device:** Google's canonicalization turns the URL into
  up to 30 host/path expressions, for example `a.b.com/1/` and `b.com/`.
  Only the first 4 bytes of each expression's SHA-256 hash are sent. The
  match is decided locally by comparing full 32-byte hashes. localhost,
  private IPs and names without a public suffix are never sent. The key
  travels in the `x-goog-api-key` header, which is Google Cloud's
  recommended form. `"api_key_in_header": false` in
  [config/safe_browsing.json](config/safe_browsing.json) switches to `?key=`.
- **Rules followed:**
  - Unknown threat types or attributes make the client ignore that detail.
  - `CANARY` and `FRAME_ONLY` details don't count as a match for a page.
  - Positive answers are cached for at most 30 minutes, because the terms
    forbid warning on older data. Empty answers are cached for
    `cacheDuration`.
  - Matches carry `threat_types` (`phishing`, `malware`, ...) and
    `attribution: "Advisory provided by Google"`.
  - Use is non-commercial only.
- **Failures:**
  - 2-second timeout.
  - One retry for network errors and 5xx.
  - No retry for 4xx.
  - Token-bucket rate limit, 60 requests a minute by default.
  - Exponential back-off: 60 s, doubling, up to 30 min. `Retry-After` on a
    429 is respected.

  Every failure is `unavailable`, never `no_match`.
- **Tests:** they cover all 33 canonicalization examples Google publishes,
  the v5 IPv6 and expression examples, and a fake Google server for caching,
  errors, rate limits and privacy.
- **Not yet verified against the real API:**
  - whether the header form of the key is accepted;
  - whether URL-safe base64 prefixes are accepted. The docs say only
    "base64", and Google's example has no padding.
- **Not implemented:** the Global Cache and local hash lists of Real-Time and
  Local List Mode. This is the plain real-time check with a local cache.
  Host suffixes use the ICANN part of the Public Suffix List, which gives a
  superset of expressions, so nothing is missed.

## Inference (Phase 4)

```powershell
python -m src.inference.bundle build          # artifacts/runs -> models/full_url (Git-ignored)
python -m src.inference.bundle verify
python -m src.inference.predict "https://example.com/login" "https://bit.ly/abc"
python -m src.inference.predict example.com --domain
python -m src.inference.predict URL --json
```

- **Model bundle** (`models/full_url/`): `cnn.pt`, `ngram.npz`,
  `redirectors.txt` and `version.json`.
  - `version.json` holds the calibrator, thresholds, validation numbers, data
    and library versions, and the SHA-256 of every file. It is the one
    manifest that replaces the spec's separate `model_config.json`,
    `tokenizer.json`, `feature_config.json` and `version.json`.
  - Loading refuses any file whose hash does not match.
  - The model version comes from the content (for example
    `full_url-edb8f2cc8642`), so the same model always has the same version.
  - To deploy, copy the whole folder.
- **Runtime** ([src/inference/runtime.py](src/inference/runtime.py)): CPU
  scoring that mirrors training exactly. A test checks it against the
  training code at batch sizes 1, 7 and 64.
- **Decision engine** ([src/inference/decision_engine.py](src/inference/decision_engine.py)),
  rules in order. Threat intelligence can only raise the risk.
  1. The exact page or host is listed as phishing: PHISHING.
  2. A link shortener or QR redirector: UNCERTAIN.
  3. No model result (domain-only input, model failure): UNCERTAIN.
  4. Otherwise the calibrated model.
  5. A malware listing: at least UNCERTAIN, but never labelled phishing.
  6. A listed sibling host: LIKELY_SAFE becomes UNCERTAIN.
- **Predictor** ([src/inference/predict.py](src/inference/predict.py)):
  - normalizes the input, de-duplicates it and checks the cache (exact URL +
    model version);
  - scores the misses in batches and looks them up in the local threat
    database;
  - gives invalid input its own error result and keeps the input order.
- **No domain-only model yet:** hostnames are checked against threat
  intelligence only and otherwise answered UNCERTAIN, as the spec requires.

First real run (laptop CPU, 2026-11-20):

| Input | Decision | Why |
|---|---|---|
| `https://en.wikipedia.org/wiki/Phishing` | LIKELY_SAFE (0.003) | model |
| `http://paypal-account-verify.secure-login-update.xyz/signin/webscr?cmd=_login` (made up) | PHISHING (0.998) | model |
| a page from the PhishTank feed / another page on that host | PHISHING | threat intel (exact / hostname) |
| `https://bit.ly/3abcXYZ` | UNCERTAIN | rule: destination hidden |
| `https://www.google.com/` | UNCERTAIN (0.345) | model |
| **`https://github.com/login`** | **PHISHING (0.968)** | **model: a false alarm** |

The last row is the "real login page" blind spot found in Phase 2. A
possible guard: on very popular websites, the model alone may say at most
UNCERTAIN, and only a threat-intel listing gives PHISHING. It never says
LIKELY_SAFE, so no domain is marked safe. Measured on validation, in-sample,
2,402 safe and 1,525 phishing websites:

| Guard on Tranco top | Safe websites flagged PHISHING | Phishing websites called PHISHING |
|---|---|---|
| none | 24 | 1,290 (84.6%) |
| 1,000 | 23 | 1,286 (84.3%) |
| 10,000 | 21 | 1,278 (83.8%) |
| 100,000 | 10 | 1,257 (82.4%) |

Validation has few top-1,000 websites (7 safe), while real browsing is mostly
on them. The guard's real benefit is therefore larger than this table shows,
and so is its cost on phishing hosted on big platforms. Known phishing pages
on those platforms are still caught by the exact-URL threat lists.

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

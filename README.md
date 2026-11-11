# Phishing Detector

A Python project workspace for building and testing phishing URL detection tools.

## Current status

This repository currently contains the project skeleton and an environment
check. The URL detection, model training, and prediction workflow is not yet
included in this checkout.

## Requirements

- Python 3.10 or newer
- Packages listed in `requirements.txt`
- PyTorch, installed separately for your operating system and hardware

## Setup

Create and activate a virtual environment, then install the project dependencies:

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

"""Print a quick report of the Python / PyTorch / hardware environment."""
from __future__ import annotations

import importlib
import platform
import sys


def check_package(name: str) -> str:
    try:
        module = importlib.import_module(name)
        return getattr(module, "__version__", "installed (no version attr)")
    except ImportError:
        return "NOT INSTALLED"


def main() -> int:
    print("=== System ===")
    print(f"Python      : {sys.version.split()[0]}")
    print(f"Platform    : {platform.system()} {platform.machine()}")

    print("\n=== Packages ===")
    for pkg in ("numpy", "pandas", "sklearn", "tldextract",
                "fastapi", "uvicorn", "pydantic", "httpx", "pytest"):
        print(f"{pkg:<12}: {check_package(pkg)}")

    print("\n=== PyTorch ===")
    try:
        import torch
    except ImportError:
        print("torch       : NOT INSTALLED (see step 4)")
        return 1

    print(f"torch       : {torch.__version__}")
    cuda_ok = torch.cuda.is_available()
    print(f"CUDA usable : {cuda_ok}")
    if cuda_ok:
        print(f"GPU         : {torch.cuda.get_device_name(0)}")
    else:
        print("GPU         : none detected, CPU training/inference will be used")

    # Tiny end-to-end sanity check: Embedding -> Conv1d on the chosen device.
    device = torch.device("cuda" if cuda_ok else "cpu")
    emb = torch.nn.Embedding(100, 16).to(device)
    conv = torch.nn.Conv1d(16, 8, kernel_size=3).to(device)
    ids = torch.randint(0, 100, (2, 50), device=device)
    out = conv(emb(ids).transpose(1, 2))
    print(f"Smoke test  : Embedding->Conv1d OK, output shape {tuple(out.shape)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
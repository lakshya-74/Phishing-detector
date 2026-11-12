"""Parsers for raw feed snapshots. Pure functions: no network, no URL visiting."""
from __future__ import annotations

import csv
import gzip
import io
import json
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .download_datasets import SOURCES

MAX_UNCOMPRESSED_BYTES = 300 * 1024 * 1024
MAX_CSV_ERRORS = 10_000
_PHISHTANK_REQUIRED = frozenset({"phish_id", "url", "submission_time", "verified"})


@dataclass(frozen=True, slots=True)
class RawRecord:
    source: str        # "phishtank" | "openphish" | "tranco"
    label: str         # "phishing" | "benign_weak"
    value: str         # raw URL or domain, untouched
    input_type: str   # "full_url" | "domain"
    source_id: str     # phish_id / rank / ""
    first_seen: str    # ISO timestamp given by the source, "" if unknown
    collected_at: str  # when WE downloaded it (from the manifest)
    source_file: str


def find_snapshots(raw_root: Path | str, source_name: str) -> list[Path]:
    """All downloaded snapshots of a source, oldest first (timestamped names sort)."""
    source = SOURCES[source_name]
    folder = Path(raw_root) / source.category / source.name
    return sorted(p for p in folder.glob(f"{source.name}_*{source.suffix}") if p.is_file())


def read_collected_at(data_path: Path | str) -> str:
    data_path = Path(data_path)
    manifest = data_path.with_name(data_path.name + ".manifest.json")
    try:
        return str(json.loads(manifest.read_text(encoding="utf-8")).get("retrieved_at", ""))
    except (OSError, ValueError, AttributeError):
        return ""


def parse_phishtank(path: Path | str, collected_at: str = "",
                    skipped: Counter[str] | None = None) -> Iterator[RawRecord]:
    path = Path(path)
    skipped = Counter() if skipped is None else skipped
    with gzip.open(path, "rt", encoding="utf-8-sig", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        if not _PHISHTANK_REQUIRED <= set(reader.fieldnames or []):
            raise ValueError("unexpected PhishTank CSV header")
        rows = iter(reader)
        errors = 0
        while True:
            try:
                row = next(rows)
            except StopIteration:
                break
            except csv.Error:
                errors += 1
                skipped["csv_error"] += 1
                if errors > MAX_CSV_ERRORS:
                    raise ValueError("too many malformed CSV rows") from None
                continue
            url = (row.get("url") or "").strip()
            if not url:
                skipped["empty_url"] += 1
                continue
            if (row.get("verified") or "").strip().lower() != "yes":
                skipped["not_verified"] += 1
                continue
            yield RawRecord(
                source="phishtank", label="phishing", value=url, input_type="full_url",
                source_id=(row.get("phish_id") or "").strip(),
                first_seen=(row.get("submission_time") or "").strip(),
                collected_at=collected_at, source_file=path.name)


def parse_openphish(path: Path | str, collected_at: str = "",
                    skipped: Counter[str] | None = None) -> Iterator[RawRecord]:
    """One URL per line. `skipped` is unused; kept for a uniform parser signature."""
    path = Path(path)
    with path.open("r", encoding="utf-8-sig", errors="replace") as fh:
        for line in fh:
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            yield RawRecord(
                source="openphish", label="phishing", value=value, input_type="full_url",
                source_id="", first_seen="", collected_at=collected_at, source_file=path.name)


def parse_tranco(path: Path | str, collected_at: str = "",
                 skipped: Counter[str] | None = None) -> Iterator[RawRecord]:
    path = Path(path)
    skipped = Counter() if skipped is None else skipped
    with zipfile.ZipFile(path) as zf:
        members = [i for i in zf.infolist() if i.filename.lower().endswith(".csv")]
        if len(members) != 1:
            raise ValueError("expected exactly one CSV file in the Tranco archive")
        if members[0].file_size > MAX_UNCOMPRESSED_BYTES:
            raise ValueError("Tranco CSV is unexpectedly large")
        with zf.open(members[0]) as raw:
            for line in io.TextIOWrapper(raw, encoding="utf-8-sig", errors="replace", newline=""):
                line = line.strip()
                if not line:
                    continue
                rank, sep, domain = line.partition(",")
                domain = domain.strip()
                if not sep or not rank.isdigit() or not domain:
                    skipped["malformed_row"] += 1
                    continue
                yield RawRecord(
                    source="tranco", label="benign_weak", value=domain, input_type="domain",
                    source_id=rank, first_seen="", collected_at=collected_at,
                    source_file=path.name)
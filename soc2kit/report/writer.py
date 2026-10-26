"""Writes the evidence pack: report.json, report.html, workbook.xlsx, evidence/*.json, manifest.json, and a zip."""
from __future__ import annotations

import hashlib
import json
import os
import zipfile
from dataclasses import asdict
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from ..runner import ScanResult
from .summary import build_summary
from .xlsx import write_workbook


def _dump(obj, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, default=str, sort_keys=False), encoding="utf-8")


def render_html(summary: dict) -> str:
    env = Environment(loader=PackageLoader("soc2kit.report", "templates"),
                      autoescape=select_autoescape(["html", "j2"]))
    return env.get_template("report.html.j2").render(s=summary)


def write_pack(scan: ScanResult, out_dir: str, make_zip: bool = True) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    summary = build_summary(scan)

    for r in scan.results:
        _dump({
            "check_id": r.check.id,
            "title": r.check.title,
            "criteria": list(r.check.criteria),
            "account_id": scan.account_id,
            "region": r.region,
            "status": r.status.value,
            "started_at": r.started_at,
            "finished_at": r.finished_at,
            "error": r.error,
            "api_calls": [asdict(e) for e in r.evidence],
        }, out / r.evidence_file)

    _dump(summary, out / "report.json")
    (out / "report.html").write_text(render_html(summary), encoding="utf-8")
    write_workbook(summary, str(out / "workbook.xlsx"))

    files = sorted(p for p in out.rglob("*") if p.is_file() and p.name not in ("manifest.json",) and p.suffix != ".zip")
    manifest = {
        "account_id": scan.account_id,
        "generated_at": scan.finished_at,
        "files": {str(p.relative_to(out)).replace(os.sep, "/"): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in files},
    }
    _dump(manifest, out / "manifest.json")

    if make_zip:
        zip_path = out / f"soc2-evidence-{scan.account_id}-{scan.finished_at[:10]}.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
            for p in files + [out / "manifest.json"]:
                z.write(p, p.relative_to(out))
    return summary

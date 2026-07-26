"""Export a 500-employee enterprise demo corpus for the SOC dashboard."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from synthetic_data.campaign_correlation.demo import DEMO_CAMPAIGN_VECTORS
from synthetic_data.demo import build_demo_feature_vectors, kind_counts

COUNT = 500
OUT_JSON = ROOT / "frontend" / "src" / "data" / "demoFeatureVectors.json"
OUT_XLSX = ROOT / "datasets" / "sentinelai_sample_batch.xlsx"


def main() -> None:
    vectors = build_demo_feature_vectors(COUNT, seed=42, spread_days=True)
    counts = kind_counts(vectors)
    employees = {v.employee_id for v in vectors}
    days = sorted({v.simulation_day for v in vectors})
    scenarios: dict[str, int] = {}
    for vector in vectors:
        if vector.demo_kind != "confirmed_attack":
            continue
        label = str(vector.extra.get("attack_scenario", "Unknown"))
        scenarios[label] = scenarios.get(label, 0) + 1

    payload = [v.to_payload() for v in vectors]
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(payload), encoding="utf-8")

    # Tabular export for offline inspection (CSV always; XLSX when openpyxl present).
    excel_note = "skipped"
    try:
        import pandas as pd

        rows = []
        for item in payload:
            row = dict(item)
            seq = row.get("event_sequence")
            if isinstance(seq, list):
                row["event_sequence"] = "|".join(str(x) for x in seq)
            rows.append(row)
        frame = pd.DataFrame(rows)
        csv_path = OUT_XLSX.with_suffix(".csv")
        frame.to_csv(csv_path, index=False)
        try:
            frame.to_excel(OUT_XLSX, index=False, engine="openpyxl")
            excel_note = f"wrote {csv_path.name} + {OUT_XLSX.name}"
        except ImportError:
            excel_note = f"wrote {csv_path.name} (install openpyxl for .xlsx)"
    except Exception as exc:  # noqa: BLE001
        excel_note = f"tabular export failed: {exc}"

    print(f"Employees: {len(employees)}")
    print(f"Rows: {len(vectors)}")
    print(f"Mix: {counts}")
    print(f"Days: {days}")
    print(f"Attack scenarios: {scenarios}")
    print(f"Campaign stages available: {len(DEMO_CAMPAIGN_VECTORS)}")
    print(f"Wrote {OUT_JSON} ({OUT_JSON.stat().st_size / 1024:.0f} KB)")
    print(f"Tabular export: {excel_note}")


if __name__ == "__main__":
    main()

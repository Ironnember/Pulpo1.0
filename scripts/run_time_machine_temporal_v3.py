#!/usr/bin/env python3
"""Measure frozen Time Machine V2 constitutional strength against Git commit time."""
from __future__ import annotations

import argparse, csv, html, json, subprocess, tempfile
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FROZEN = "2bad0db3675f0ea8ccdc0a1188be576f1a59e4e8"
CHECKPOINTS = 37
INVARIANTS = 14
WINDOWS = (6, 12, 24, 48)


def run(cmd, check=True):
    return subprocess.run(cmd, cwd=ROOT, check=check, text=True, capture_output=True)


def dt(value):
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"timezone required: {value}")
    return parsed


def meta(sha):
    out = run(["git", "show", "-s", "--format=%H%x00%cI%x00%aI%x00%s", sha]).stdout.rstrip("\n")
    commit, committed_at, authored_at, subject = out.split("\x00", 3)
    return commit, committed_at, authored_at, subject


def fresh_v2():
    with tempfile.TemporaryDirectory(prefix="pulpo-tm-v3-") as directory:
        prefix = Path(directory) / "v2"
        done = run(["python", str(ROOT / "scripts/run_time_machine_lineage_v2.py"), "--output-prefix", str(prefix)], check=False)
        evidence = prefix.with_suffix(".json")
        if not evidence.exists():
            raise RuntimeError(f"fresh V2 emitted no JSON; rc={done.returncode}")
        report = json.loads(evidence.read_text(encoding="utf-8"))
        if done.returncode != 0 or report.get("result") != "pass":
            raise RuntimeError(f"fresh V2 failed; rc={done.returncode}; result={report.get('result')}")
        return report


def enrich(v2):
    out, previous = [], None
    for index, item in enumerate(v2["checkpoints"], 1):
        commit, committed_at, authored_at, _ = meta(item["sha"])
        if commit != item["sha"]:
            raise RuntimeError(f"SHA mismatch at checkpoint {index}")
        committed, authored = dt(committed_at), dt(authored_at)
        if previous is not None and committed < previous:
            raise RuntimeError(f"temporal_clock_anomaly at {commit}")
        previous = committed
        row = dict(item)
        row.update({
            "committed_at": committed_at,
            "git_authored_at": authored_at,
            "author_committer_delta_seconds": (committed - authored).total_seconds(),
        })
        out.append(row)
    return out


def change_points(checkpoints):
    points, previous_strength, previous = [], None, None
    for cp in checkpoints:
        strength = float(cp["absolute_strength"])
        if previous_strength is None or strength != previous_strength:
            point = {
                "sha": cp["sha"], "committed_at": cp["committed_at"], "subject": cp["subject"],
                "absolute_strength": strength, "implemented_health": cp["implemented_health"],
                "holds": cp["counts"]["hold"], "fails": cp["counts"]["fail"],
            }
            if previous is None:
                point.update(dwell_hours=None, controls_gained=0, percentage_points_gained=0.0,
                             controls_gained_per_day=None, period_label="origin")
            else:
                hours = (dt(point["committed_at"]) - dt(previous["committed_at"])).total_seconds() / 3600
                gained = point["holds"] - previous["holds"]
                rate = gained / (hours / 24) if hours else None
                point.update(
                    dwell_hours=round(hours, 6), controls_gained=gained,
                    percentage_points_gained=round(strength - previous["absolute_strength"], 6),
                    controls_gained_per_day=round(rate, 6) if rate is not None else None,
                    period_label="burst" if hours <= 6 and gained > 0 else "gain",
                )
            points.append(point)
            previous, previous_strength = point, strength
    return points


def first_holds(checkpoints):
    seen, events = set(), []
    ids = list(checkpoints[-1]["invariants"])
    for cp in checkpoints:
        for invariant in ids:
            if invariant not in seen and cp["invariants"][invariant]["status"] == "hold":
                seen.add(invariant)
                events.append({"invariant_id": invariant, "sha": cp["sha"], "committed_at": cp["committed_at"]})
    return events


def rolling(events, hours):
    times = [dt(e["committed_at"]) for e in events]
    left = best_start = best_end = best = 0
    for right, current in enumerate(times):
        while left <= right and (current - times[left]).total_seconds() > hours * 3600:
            left += 1
        if right - left + 1 > best:
            best, best_start, best_end = right - left + 1, left, right
    if not events:
        return {"hours": hours, "max_new_holds": 0, "start": None, "end": None, "invariants": []}
    return {"hours": hours, "max_new_holds": best, "start": events[best_start]["committed_at"],
            "end": events[best_end]["committed_at"],
            "invariants": [e["invariant_id"] for e in events[best_start:best_end + 1]]}


def weighted_strength(checkpoints):
    weighted = total = 0.0
    for current, following in zip(checkpoints, checkpoints[1:]):
        seconds = (dt(following["committed_at"]) - dt(current["committed_at"])).total_seconds()
        if seconds < 0:
            raise RuntimeError("temporal_clock_anomaly")
        weighted += float(current["absolute_strength"]) * seconds
        total += seconds
    return round(weighted / total, 6) if total else float(checkpoints[-1]["absolute_strength"])


def hours(a, b):
    return round((dt(b["committed_at"]) - dt(a["committed_at"])).total_seconds() / 3600, 6)


def build(v2, checkpoints):
    if len(checkpoints) != CHECKPOINTS or int(v2.get("invariant_count", -1)) != INVARIANTS:
        raise RuntimeError("frozen V2 shape mismatch")
    final = checkpoints[-1]
    if final["sha"] != FROZEN or final["counts"]["hold"] != INVARIANTS or float(final["absolute_strength"]) != 100:
        raise RuntimeError("frozen endpoint mismatch")
    if v2.get("probe_error_count") != 0 or v2.get("unresolved_regression_count") != 0:
        raise RuntimeError("fresh V2 contains errors or unresolved regression")

    points, events = change_points(checkpoints), first_holds(checkpoints)
    if len(events) != INVARIANTS:
        raise RuntimeError("not all frozen invariants reached hold")
    first = checkpoints[0]
    first_nonzero = next(c for c in checkpoints if float(c["absolute_strength"]) > 0)
    first_50 = next(c for c in checkpoints if float(c["absolute_strength"]) >= 50)
    first_100 = next(c for c in checkpoints if float(c["absolute_strength"]) == 100)
    longest = max(points[1:], key=lambda p: p["dwell_hours"])
    span_hours = hours(first, final)
    span_days = span_hours / 24
    clock_deltas = [abs(float(c["author_committer_delta_seconds"])) for c in checkpoints]

    return {
        "schema": "pulpo.time-machine-temporal.v3", "result": "pass",
        "frozen_canonical_sha": FROZEN, "authority_effect": "none", "provider_write_attempted": False,
        "checkpoint_count": len(checkpoints), "invariant_count": INVARIANTS,
        "v2_result": v2["result"], "v2_probe_error_count": v2["probe_error_count"],
        "v2_historical_regression_count": v2["historical_regression_count"],
        "v2_unresolved_regression_count": v2["unresolved_regression_count"],
        "current_absolute_strength": final["absolute_strength"], "current_implemented_health": final["implemented_health"],
        "elapsed": {
            "first_checkpoint_to_first_100_hours": hours(first, first_100),
            "first_nonzero_to_first_100_hours": hours(first_nonzero, first_100),
            "first_50_to_first_100_hours": hours(first_50, first_100),
            "observed_span_hours": span_hours, "terminal_100_plateau_hours": hours(first_100, final),
        },
        "rates": {
            "canonical_checkpoint_arrivals_per_day": round((len(checkpoints)-1)/span_days, 6),
            "constitutional_hold_admissions_per_day": round(INVARIANTS/span_days, 6),
        },
        "time_weighted_average_absolute_strength": weighted_strength(checkpoints),
        "longest_prechange_plateau": {"hours": longest["dwell_hours"], "ending_sha": longest["sha"],
                                      "ending_strength": longest["absolute_strength"], "subject": longest["subject"]},
        "rolling_new_holds": {str(w): rolling(events, w) for w in WINDOWS},
        "author_committer_clock": {
            "checkpoints_with_nonzero_delta": sum(1 for d in clock_deltas if d > 0),
            "max_absolute_delta_seconds": round(max(clock_deltas), 6) if clock_deltas else 0,
        },
        "first_hold_events": events, "change_points": points, "checkpoints": checkpoints,
    }


def write_csv(path, report):
    fields = ["index", "sha", "committed_at", "subject", "absolute_strength", "implemented_health", "holds", "fails",
              "dwell_hours", "controls_gained", "percentage_points_gained", "controls_gained_per_day", "period_label"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields); writer.writeheader()
        for index, point in enumerate(report["change_points"], 1):
            writer.writerow({"index": index, **{field: point.get(field) for field in fields if field != "index"}})


def write_md(path, report):
    e, r = report["elapsed"], report["rates"]
    lines = ["# Time Machine V3 — Constitutional Strength Over Time", "", f"Result: **{report['result'].upper()}**", "",
             f"- Checkpoints: **{report['checkpoint_count']}**", f"- Frozen invariants: **{report['invariant_count']}**",
             f"- Current strength: **{report['current_absolute_strength']:.2f}/100**",
             f"- Initial checkpoint → first 100%: **{e['first_checkpoint_to_first_100_hours']:.2f} h**",
             f"- First non-zero → first 100%: **{e['first_nonzero_to_first_100_hours']:.2f} h**",
             f"- First 50% → first 100%: **{e['first_50_to_first_100_hours']:.2f} h**",
             f"- Time-weighted average strength: **{report['time_weighted_average_absolute_strength']:.2f}/100**",
             f"- Canonical checkpoint arrivals: **{r['canonical_checkpoint_arrivals_per_day']:.2f}/day**",
             f"- Constitutional hold admissions: **{r['constitutional_hold_admissions_per_day']:.2f}/day**",
             f"- V2 post-admission regressions: **{report['v2_historical_regression_count']}**", "", "## Change points", "",
             "| Commit time | Strength | Holds | Dwell h | +controls | controls/day | Label | SHA |",
             "|---|---:|---:|---:|---:|---:|---|---|"]
    for p in report["change_points"]:
        dwell = "—" if p["dwell_hours"] is None else f"{p['dwell_hours']:.2f}"
        rate = "—" if p["controls_gained_per_day"] is None else f"{p['controls_gained_per_day']:.2f}"
        lines.append(f"| {p['committed_at']} | {p['absolute_strength']:.2f} | {p['holds']} | {dwell} | {p['controls_gained']} | {rate} | {p['period_label']} | `{p['sha'][:12]}` |")
    lines += ["", "## Rolling admission bursts", ""]
    for w in WINDOWS:
        lines.append(f"- {w} h: **{report['rolling_new_holds'][str(w)]['max_new_holds']}** new canonical holds")
    lines += ["", "## Claim boundary", "",
              "These are Git admission-time measurements for the frozen 14-control software catalog. They do not measure engineering-hours worked, autonomous intelligence growth, causal compounding, exhaustive security, hardware-backed human authority, or real-world provider consequence.", ""]
    path.write_text("\n".join(lines), encoding="utf-8")


def write_svg(path, report):
    points = report["change_points"]; width, height = 1000, 460; left, right, top, bottom = 75, 35, 35, 65
    pw, ph = width-left-right, height-top-bottom; start = dt(points[0]["committed_at"]); end = dt(report["checkpoints"][-1]["committed_at"])
    total = max((end-start).total_seconds(), 1)
    x = lambda p: left + ((dt(p["committed_at"])-start).total_seconds()/total)*pw
    y = lambda value: top + (100-float(value))/100*ph
    steps = []
    for i,p in enumerate(points):
        px,py=x(p),y(p["absolute_strength"])
        if i: steps += [(px,steps[-1][1]),(px,py)]
        else: steps.append((px,py))
    steps.append((left+pw,steps[-1][1])); poly=" ".join(f"{a:.1f},{b:.1f}" for a,b in steps)
    grid="".join(f'<line x1="{left}" y1="{y(v):.1f}" x2="{left+pw}" y2="{y(v):.1f}" opacity="0.15"/><text x="{left-12}" y="{y(v)+4:.1f}" text-anchor="end">{v}</text>' for v in (0,25,50,75,100))
    dots="".join(f'<circle cx="{x(p):.1f}" cy="{y(p["absolute_strength"]):.1f}" r="4"><title>{html.escape(p["committed_at"])} — {p["absolute_strength"]:.2f}</title></circle>' for p in points)
    svg=f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}"><style>text{{font-family:system-ui,sans-serif;fill:currentColor}} line,polyline{{stroke:currentColor;fill:none}} circle{{fill:currentColor}}</style><text x="{left}" y="22" font-size="18" font-weight="600">Pulpo Time Machine V3 — Constitutional Strength Over Git Time</text>{grid}<polyline points="{poly}" stroke-width="3"/>{dots}<line x1="{left}" y1="{top+ph}" x2="{left+pw}" y2="{top+ph}"/><text x="{left}" y="{height-25}">{start.date()}</text><text x="{left+pw}" y="{height-25}" text-anchor="end">{end.date()}</text></svg>'''
    path.write_text(svg, encoding="utf-8")


def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--output-prefix", default="time-machine-v3"); args=parser.parse_args()
    try:
        v2=fresh_v2(); checkpoints=enrich(v2); report=build(v2, checkpoints)
    except Exception as exc:
        print(json.dumps({"schema":"pulpo.time-machine-temporal.v3","result":"fail","authority_effect":"none","provider_write_attempted":False,"error":{"type":type(exc).__name__,"message":str(exc)}}, indent=2, sort_keys=True)); return 1
    prefix=Path(args.output_prefix); jp=prefix.with_suffix(".json"); cp=prefix.with_suffix(".csv"); mp=prefix.with_suffix(".md"); sp=prefix.with_suffix(".svg")
    jp.write_text(json.dumps(report, indent=2, sort_keys=True)+"\n", encoding="utf-8"); write_csv(cp,report); write_md(mp,report); write_svg(sp,report)
    e=report["elapsed"]
    print(json.dumps({"schema":report["schema"],"result":"pass","authority_effect":"none","provider_write_attempted":False,"checkpoint_count":report["checkpoint_count"],"invariant_count":report["invariant_count"],"current_absolute_strength":report["current_absolute_strength"],"first_checkpoint_to_first_100_hours":e["first_checkpoint_to_first_100_hours"],"first_nonzero_to_first_100_hours":e["first_nonzero_to_first_100_hours"],"first_50_to_first_100_hours":e["first_50_to_first_100_hours"],"time_weighted_average_absolute_strength":report["time_weighted_average_absolute_strength"],"longest_prechange_plateau_hours":report["longest_prechange_plateau"]["hours"],"rolling_new_holds":{k:v["max_new_holds"] for k,v in report["rolling_new_holds"].items()},"v2_historical_regression_count":report["v2_historical_regression_count"],"outputs":[str(jp),str(cp),str(mp),str(sp)]}, indent=2, sort_keys=True)); return 0

if __name__ == "__main__": raise SystemExit(main())

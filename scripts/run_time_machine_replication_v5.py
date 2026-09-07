#!/usr/bin/env python3
"""Run Time Machine V5 frozen-suite causal replication with a placebo mapping."""
from __future__ import annotations

import csv
import hashlib
import html
import json
from pathlib import Path
import statistics
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
V4_FREEZE_SHA = "15eb61fcb63adda6acd02473db0535b4ff0b201d"
V5_FREEZE_SHA = "6115cd8251a45bb91976d3fc414d5f8a969f7563"
V4_CONTRACT_PATH = "experiments/time_machine_v4/FROZEN_CONTRACT.md"
V5_CONTRACT_PATH = "experiments/time_machine_v5/FROZEN_CONTRACT.md"

TASKS = [
    {"id":"T0","answer":"C_EXECUTION_REVALIDATE","tokens":{"issued_before_change","authority_changed_before_effect","repair_needed"}},
    {"id":"T1","answer":"C_EXACT_OBJECT_RERESOLVE","tokens":{"approved_immutable_object","mutable_reference_changed","repair_needed"}},
    {"id":"T2","answer":"C_TRUSTED_MONOTONIC_TIME","tokens":{"expiry_sensitive","untrusted_clock_rollback","repair_needed"}},
    {"id":"T3","answer":"C_INDEPENDENT_READBACK","tokens":{"executor_claim","independent_effect_unknown","repair_needed"}},
    {"id":"T4","answer":"C_BLOCK_ON_EVIDENCE_CONVERGENCE","tokens":{"protected_transition_advanced","evidence_obligation_unresolved","repair_needed"}},
    {"id":"T5","answer":"C_DURABLE_REPLAY_STATE","tokens":{"one_use_consumed","process_restart","repair_needed"}},
    {"id":"T6","answer":"C_APPROVAL_EXACT_BINDING","tokens":{"signed_approval","request_or_policy_substitution","repair_needed"}},
    {"id":"T7","answer":"C_MONOTONIC_CAS","tokens":{"concurrent_writers","stale_head","repair_needed"}},
]

CANDIDATES = [
    "C_LOG_ONLY","C_RETRY_WITH_BACKOFF","C_BROADEN_SCOPE","C_EXTEND_TTL","C_TRUST_PROVIDER_ACK",
    "C_EXECUTION_REVALIDATE","C_EXACT_OBJECT_RERESOLVE","C_TRUSTED_MONOTONIC_TIME","C_INDEPENDENT_READBACK",
    "C_BLOCK_ON_EVIDENCE_CONVERGENCE","C_DURABLE_REPLAY_STATE","C_APPROVAL_EXACT_BINDING","C_MONOTONIC_CAS",
]

LESSONS = [
    {"id":"L_EXECUTION_AUTHORITY_CONTINUITY","triggers":{"issued_before_change","authority_changed_before_effect"},"favors":"C_EXECUTION_REVALIDATE","authority_effect":"none","invalidated":False},
    {"id":"L_EXACT_OBJECT_CONTINUITY","triggers":{"approved_immutable_object","mutable_reference_changed"},"favors":"C_EXACT_OBJECT_RERESOLVE","authority_effect":"none","invalidated":False},
    {"id":"L_TRUSTED_TIME_OWNERSHIP","triggers":{"expiry_sensitive","untrusted_clock_rollback"},"favors":"C_TRUSTED_MONOTONIC_TIME","authority_effect":"none","invalidated":False},
    {"id":"L_OUTCOME_NEEDS_OBSERVATION","triggers":{"executor_claim","independent_effect_unknown"},"favors":"C_INDEPENDENT_READBACK","authority_effect":"none","invalidated":False},
    {"id":"L_ACCOUNTABLE_TRANSITION","triggers":{"protected_transition_advanced","evidence_obligation_unresolved"},"favors":"C_BLOCK_ON_EVIDENCE_CONVERGENCE","authority_effect":"none","invalidated":False},
    {"id":"L_REPLAY_SURVIVES_RESTART","triggers":{"one_use_consumed","process_restart"},"favors":"C_DURABLE_REPLAY_STATE","authority_effect":"none","invalidated":False},
    {"id":"L_APPROVAL_EXACTNESS","triggers":{"signed_approval","request_or_policy_substitution"},"favors":"C_APPROVAL_EXACT_BINDING","authority_effect":"none","invalidated":False},
    {"id":"L_MONOTONIC_CUSTODY_HEAD","triggers":{"concurrent_writers","stale_head"},"favors":"C_MONOTONIC_CAS","authority_effect":"none","invalidated":False},
    {"id":"L_POISON_EXPAND_WORKER","triggers":{"repair_needed"},"favors":"C_BROADEN_SCOPE","authority_effect":"expand","invalidated":False,"retrieval_score":0.999},
    {"id":"L_STALE_TRUST_ACK","triggers":{"executor_claim"},"favors":"C_TRUST_PROVIDER_ACK","authority_effect":"none","invalidated":True,"retrieval_score":0.998},
]


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, check=True, text=True, capture_output=True).stdout


def verify_freezes() -> dict[str, Any]:
    v4_frozen = git("show", f"{V4_FREEZE_SHA}:{V4_CONTRACT_PATH}").encode()
    v4_current = (ROOT / V4_CONTRACT_PATH).read_bytes()
    if v4_frozen != v4_current:
        raise RuntimeError("V4 frozen contract changed after its freeze commit")
    v5_frozen = git("show", f"{V5_FREEZE_SHA}:{V5_CONTRACT_PATH}").encode()
    v5_current = (ROOT / V5_CONTRACT_PATH).read_bytes()
    if v5_frozen != v5_current:
        raise RuntimeError("V5 frozen contract changed after its freeze commit")
    if git("rev-parse", V4_FREEZE_SHA).strip() != V4_FREEZE_SHA:
        raise RuntimeError("V4 freeze SHA does not resolve exactly")
    if git("rev-parse", V5_FREEZE_SHA).strip() != V5_FREEZE_SHA:
        raise RuntimeError("V5 freeze SHA does not resolve exactly")
    return {
        "v4_freeze_sha": V4_FREEZE_SHA,
        "v5_freeze_sha": V5_FREEZE_SHA,
        "v4_contract_sha256": hashlib.sha256(v4_frozen).hexdigest(),
        "v5_contract_sha256": hashlib.sha256(v5_frozen).hexdigest(),
    }


def baseline_key(task_id: str, candidate: str) -> str:
    return hashlib.sha256(f"baseline|{task_id}|{candidate}".encode()).hexdigest()


def build_placebo_mapping() -> tuple[dict[str, str], list[str]]:
    valid = [x for x in LESSONS if x["authority_effect"] == "none" and not x["invalidated"]]
    ordered = sorted(valid, key=lambda x: hashlib.sha256(f"placebo|{V5_FREEZE_SHA}|{x['id']}".encode()).hexdigest())
    original = [x["favors"] for x in ordered]
    if len(original) != len(set(original)):
        raise RuntimeError("placebo source favored candidates are not unique")
    rotated = original[1:] + original[:1]
    mapping = {lesson["id"]: candidate for lesson, candidate in zip(ordered, rotated)}
    fixed = [lesson["id"] for lesson in ordered if mapping[lesson["id"]] == lesson["favors"]]
    if fixed:
        raise RuntimeError(f"placebo mapping contains fixed points: {fixed}")
    return mapping, [x["id"] for x in ordered]


def run_arm(task: dict[str, Any], condition: str, placebo: dict[str, str]) -> dict[str, Any]:
    priorities = {candidate: 0 for candidate in CANDIDATES}
    rejected_lessons: list[dict[str, str]] = []
    accepted_lessons: list[str] = []
    if condition in {"K+", "P+"}:
        for lesson in LESSONS:
            if lesson["authority_effect"] != "none":
                rejected_lessons.append({"id":lesson["id"],"reason":"authority_expansion_forbidden"})
                continue
            if lesson["invalidated"]:
                rejected_lessons.append({"id":lesson["id"],"reason":"invalidated"})
                continue
            accepted_lessons.append(lesson["id"])
            overlap = len(task["tokens"] & lesson["triggers"])
            favored = lesson["favors"] if condition == "K+" else placebo[lesson["id"]]
            priorities[favored] = max(priorities[favored], overlap)
    elif condition != "B0":
        raise ValueError(condition)

    ordered = sorted(CANDIDATES, key=lambda c: (-priorities[c], baseline_key(task["id"], c)))
    attempts = []
    for candidate in ordered:
        accepted = candidate == task["answer"]
        attempts.append({
            "attempt":len(attempts)+1,
            "candidate":candidate,
            "priority":priorities[candidate],
            "accepted":accepted,
            "cost":1,
        })
        if accepted:
            break
    return {
        "condition":condition,
        "attempts":len(attempts),
        "rejected_attempts":len(attempts)-1,
        "total_attempt_cost":len(attempts),
        "accepted_candidate":attempts[-1]["candidate"],
        "accepted_matches_frozen_evaluator":attempts[-1]["accepted"],
        "attempt_path":attempts,
        "rejected_lessons":rejected_lessons,
        "accepted_lesson_ids":accepted_lessons,
        "priorities":priorities,
    }


def aggregate(task_results: list[dict[str, Any]], arm_key: str) -> dict[str, Any]:
    attempts = [row[arm_key]["attempts"] for row in task_results]
    return {
        "total_attempts":sum(attempts),
        "mean_attempts":sum(attempts)/len(attempts),
        "median_attempts":statistics.median(attempts),
        "min_attempts":min(attempts),
        "max_attempts":max(attempts),
        "attempts_by_task":attempts,
    }


def paired_summary(values: list[int], positive_label: str, negative_label: str) -> dict[str, Any]:
    return {
        "mean_delta":sum(values)/len(values),
        "median_delta":statistics.median(values),
        positive_label:sum(1 for v in values if v > 0),
        "equal":sum(1 for v in values if v == 0),
        negative_label:sum(1 for v in values if v < 0),
        "deltas_by_task":values,
    }


def validate_safety(arm: dict[str, Any]) -> None:
    rejected = {x["id"]:x["reason"] for x in arm["rejected_lessons"]}
    if rejected.get("L_POISON_EXPAND_WORKER") != "authority_expansion_forbidden":
        raise RuntimeError(f"{arm['condition']} failed poison authority rejection")
    if rejected.get("L_STALE_TRUST_ACK") != "invalidated":
        raise RuntimeError(f"{arm['condition']} failed stale lesson rejection")


def write_csv(path: Path, report: dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        fields=["task_id","arm","attempts","rejected_attempts","accepted_candidate","delta_B0_K","delta_P_K"]
        writer=csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in report["tasks"]:
            for arm_key, arm_name in (("baseline","B0"),("verified","K+"),("placebo","P+")):
                arm=row[arm_key]
                writer.writerow({
                    "task_id":row["task_id"],"arm":arm_name,"attempts":arm["attempts"],
                    "rejected_attempts":arm["rejected_attempts"],"accepted_candidate":arm["accepted_candidate"],
                    "delta_B0_K":row["delta_B0_K"],"delta_P_K":row["delta_P_K"],
                })


def write_md(path: Path, report: dict[str, Any]) -> None:
    agg=report["aggregate"]
    lines=[
        "# Time Machine V5 — Frozen-Suite Replication + Placebo", "",
        f"Result: **{report['result'].upper()}**", "",
        f"V4 freeze: `{report['v4_freeze_sha']}`", f"V5 freeze: `{report['v5_freeze_sha']}`", "",
        "## Task-level replication", "",
        "| Task | B0 attempts | K+ attempts | P+ attempts | B0-K+ | P+-K+ |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for row in report["tasks"]:
        lines.append(f"| {row['task_id']} | {row['baseline']['attempts']} | {row['verified']['attempts']} | {row['placebo']['attempts']} | {row['delta_B0_K']} | {row['delta_P_K']} |")
    lines += [
        "", "## Aggregate attempts", "",
        "| Arm | Total | Mean | Median | Min | Max |", "|---|---:|---:|---:|---:|---:|",
    ]
    for key,label in (("baseline","B0"),("verified","K+"),("placebo","P+")):
        a=agg[key]
        lines.append(f"| {label} | {a['total_attempts']} | {a['mean_attempts']:.3f} | {a['median_attempts']:.3f} | {a['min_attempts']} | {a['max_attempts']} |")
    kb=agg["k_vs_baseline"]; kp=agg["k_vs_placebo"]
    lines += [
        "", "## Paired effects", "",
        f"- K+ vs B0 total relative reduction: **{agg['k_vs_baseline_total_relative_reduction']*100:.2f}%**",
        f"- K+ vs B0 mean paired delta: **{kb['mean_delta']:.3f} attempts**; positive/equal/negative: **{kb['k_better']}/{kb['equal']}/{kb['k_worse']}**.",
        f"- K+ vs P+ total relative reduction: **{agg['k_vs_placebo_total_relative_reduction']*100:.2f}%**",
        f"- K+ vs P+ mean paired delta: **{kp['mean_delta']:.3f} attempts**; K+ better/equal/worse: **{kp['k_better']}/{kp['equal']}/{kp['k_worse']}**.",
        "", "## Safety", "",
        "- Poisoned authority-expanding lesson rejected in K+ and P+ on all 8 tasks.",
        "- Invalidated stale lesson rejected in K+ and P+ on all 8 tasks.",
        "- Placebo mapping has zero fixed lesson->candidate associations.",
        "- `authority_effect=none`", "- `provider_write_attempted=false`", "- `model_inference_attempted=false`", "",
        "## Claim boundary", "",
        "This result applies only to the complete eight-task family frozen before V4 execution and to this deterministic repair-search harness. It does not prove general language-model learning, model-weight change, autonomous intelligence growth, exponential compounding, arbitrary domain generalization, production authority safety, external custody, or real-world consequence readiness.", "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def write_svg(path: Path, report: dict[str, Any]) -> None:
    agg=report["aggregate"]
    vals=[agg["baseline"]["total_attempts"],agg["verified"]["total_attempts"],agg["placebo"]["total_attempts"]]
    labels=["B0 uninformed","K+ verified","P+ placebo"]
    w,h=900,400; left,top,bottom=90,55,75; plot_h=h-top-bottom; maxv=max(vals+[1]); bw=150; xs=[140,375,610]
    y=lambda v: top+plot_h-(v/maxv)*plot_h
    bh=lambda v:(v/maxv)*plot_h
    rects=[]
    for x,v,label in zip(xs,vals,labels):
        rects.append(f'<rect x="{x}" y="{y(v)}" width="{bw}" height="{bh(v)}"/><text x="{x+bw/2}" y="{y(v)-10}" text-anchor="middle" font-size="20">{v}</text><text x="{x+bw/2}" y="{h-35}" text-anchor="middle">{html.escape(label)}</text>')
    svg=f'''<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}"><style>text{{font-family:system-ui,sans-serif;fill:currentColor}} line,rect{{stroke:currentColor;fill:none}}</style><text x="{left}" y="28" font-size="18" font-weight="600">Time Machine V5 — Total attempts across 8 frozen tasks</text><line x1="{left}" y1="{top+plot_h}" x2="{w-35}" y2="{top+plot_h}"/>{''.join(rects)}</svg>'''
    path.write_text(svg, encoding="utf-8")


def main() -> int:
    output_prefix=Path(sys.argv[1]) if len(sys.argv)>1 else Path("time-machine-v5")
    try:
        freeze=verify_freezes()
        placebo, placebo_order=build_placebo_mapping()
        rows=[]
        for task in TASKS:
            b=run_arm(task,"B0",placebo)
            k=run_arm(task,"K+",placebo)
            p=run_arm(task,"P+",placebo)
            if not all(x["accepted_matches_frozen_evaluator"] for x in (b,k,p)):
                raise RuntimeError(f"one or more arms failed frozen evaluator on {task['id']}")
            validate_safety(k); validate_safety(p)
            rows.append({
                "task_id":task["id"],"frozen_acceptance_candidate":task["answer"],
                "baseline":b,"verified":k,"placebo":p,
                "delta_B0_K":b["attempts"]-k["attempts"],
                "delta_P_K":p["attempts"]-k["attempts"],
            })
        a_b=aggregate(rows,"baseline"); a_k=aggregate(rows,"verified"); a_p=aggregate(rows,"placebo")
        deltas_b=[r["delta_B0_K"] for r in rows]; deltas_p=[r["delta_P_K"] for r in rows]
        report={
            "schema":"pulpo.time-machine-replication.v5","result":"pass",
            "authority_effect":"none","provider_write_attempted":False,"model_inference_attempted":False,
            **freeze,"task_count":len(TASKS),"candidate_count":len(CANDIDATES),"lesson_count":len(LESSONS),
            "placebo_mapping":placebo,"placebo_lesson_order":placebo_order,"placebo_fixed_points":0,
            "tasks":rows,
            "aggregate":{
                "baseline":a_b,"verified":a_k,"placebo":a_p,
                "k_vs_baseline":paired_summary(deltas_b,"k_better","k_worse"),
                "k_vs_placebo":paired_summary(deltas_p,"k_better","k_worse"),
                "k_vs_baseline_total_relative_reduction":(a_b["total_attempts"]-a_k["total_attempts"])/a_b["total_attempts"],
                "k_vs_placebo_total_relative_reduction":(a_p["total_attempts"]-a_k["total_attempts"])/a_p["total_attempts"],
            },
        }
    except Exception as exc:
        print(json.dumps({"schema":"pulpo.time-machine-replication.v5","result":"fail","authority_effect":"none","provider_write_attempted":False,"model_inference_attempted":False,"error":{"type":type(exc).__name__,"message":str(exc)}},indent=2,sort_keys=True)); return 1

    jp=output_prefix.with_suffix(".json"); cp=output_prefix.with_suffix(".csv"); mp=output_prefix.with_suffix(".md"); sp=output_prefix.with_suffix(".svg")
    jp.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf-8"); write_csv(cp,report); write_md(mp,report); write_svg(sp,report)
    a=report["aggregate"]
    print(json.dumps({
        "schema":report["schema"],"result":report["result"],"v4_freeze_sha":report["v4_freeze_sha"],"v5_freeze_sha":report["v5_freeze_sha"],
        "task_count":report["task_count"],"baseline_total_attempts":a["baseline"]["total_attempts"],"verified_total_attempts":a["verified"]["total_attempts"],"placebo_total_attempts":a["placebo"]["total_attempts"],
        "k_vs_baseline_relative_reduction":a["k_vs_baseline_total_relative_reduction"],"k_vs_placebo_relative_reduction":a["k_vs_placebo_total_relative_reduction"],
        "k_vs_baseline_counts":{k:a["k_vs_baseline"][k] for k in ("k_better","equal","k_worse")},
        "k_vs_placebo_counts":{k:a["k_vs_placebo"][k] for k in ("k_better","equal","k_worse")},
        "placebo_fixed_points":report["placebo_fixed_points"],"authority_effect":report["authority_effect"],"provider_write_attempted":report["provider_write_attempted"],"model_inference_attempted":report["model_inference_attempted"],
        "outputs":[str(jp),str(cp),str(mp),str(sp)],
    },indent=2,sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

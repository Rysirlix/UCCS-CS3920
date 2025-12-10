#!/usr/bin/env python3

import argparse
import json
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

from graph import AttackGraph
from planner import rank_paths, edge_risk_contributions, explain_path, suggest_mitigations
from env_tools import validate_env


def load_env(path):
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Environment file not found: {p}")
    text = p.read_text()
    if p.suffix.lower() in (".yaml", ".yml"):
        if not yaml:
            raise RuntimeError("PyYAML is required to read YAML files.")
        return yaml.safe_load(text)
    return json.loads(text)


def print_path_table(ranked, max_steps=6):
    if not ranked:
        print("No paths found.")
        return

    header = (
        f"{'Rank':<4} {'U':>8} {'Psucc':>8} {'Impact':>8} "
        f"{'Detect':>8} {'Time':>6} {'E[L]':>8}   Steps"
    )
    print(header)
    print("-" * len(header))

    for idx, r in enumerate(ranked, 1):
        steps = [e.get("technique", "?") for e in r["path"]]
        if len(steps) > max_steps:
            steps_str = " -> ".join(steps[:max_steps]) + " -> ..."
        else:
            steps_str = " -> ".join(steps)

        print(
            f"{idx:<4} "
            f"{r['utility']:>8.3f} "
            f"{r['prob']:>8.3f} "
            f"{r['impact']:>8.2f} "
            f"{r['detect']:>8.2f} "
            f"{r['time']:>6.2f} "
            f"{r['expected_loss']:>8.2f}   "
            f"{steps_str}"
        )


def cmd_plan(args):
    cfg = load_env(args.env)

    report = build_report(
        cfg,
        max_depth=args.max_depth,
        top_k=args.top_k,
        wI=args.wI,
        wD=args.wD,
        wT=args.wT,
        wP=args.wP,
    )

    ranked = []
    for p in report["paths"]:
        ranked.append({
            "utility": p["utility"],
            "prob": p["probability"],
            "impact": p["impact"],
            "detect": p["detect"],
            "time": p["time"],
            "expected_loss": p["expected_loss"],
            "path": [
                {
                    "technique": step["technique"],
                    "src": step["src"],
                    "dst": step["dst"],
                }
                for step in p["steps"]
            ],
        })

    print_path_table(ranked)

    if args.json_out:
        out_path = Path(args.json_out)
        out_path.write_text(json.dumps(report, indent=2))
        print()
        print(f"JSON report written to {out_path}")


def cmd_edges(args):
    cfg = load_env(args.env)
    g = AttackGraph(cfg["assets"], cfg["start_nodes"], cfg["goal_nodes"], cfg["edges"])
    paths = g.enumerate_paths(max_depth=args.max_depth)
    ranked = rank_paths(paths, top_k=args.top_k)
    contrib = edge_risk_contributions(ranked)

    items = sorted(contrib.items(), key=lambda kv: kv[1], reverse=True)
    print(f"Top {args.limit} edges by aggregated expected loss contribution:")
    print(f"{'Rank':<4} {'Src':<20} {'Dst':<25} {'Technique':<35} {'E[L] contrib':>12}")
    print("-" * 100)
    for i, (key, val) in enumerate(items[: args.limit], 1):
        src, dst, tech = key
        print(f"{i:<4} {src:<20} {dst:<25} {tech:<35} {val:>12.2f}")

    if args.mitigations > 0:
        print()
        print(f"Top {args.mitigations} technique-level mitigations:")
        print("-" * 100)
        mitigs = suggest_mitigations(contrib, limit=args.mitigations)
        for i, m in enumerate(mitigs, 1):
            tech_id = m["tech_id"]
            total = m["total_expected_loss"]
            print(f"{i}. {tech_id}  (total E[L] ≈ {total:.2f})")
            print(f"   Mitigation: {m['mitigation']}")
            if m["examples"]:
                print("   Example edges:")
                for ex in m["examples"]:
                    print(
                        f"     - {ex['src']} -> {ex['dst']} "
                        f"via {ex['technique']} "
                        f"(E[L] ≈ {ex['edge_expected_loss']:.2f})"
                    )
            print("-" * 100)


def cmd_validate(args):
    cfg = load_env(args.env)
    msgs = validate_env(cfg)
    if not msgs:
        print(f"{args.env}: OK (no issues found)")
    else:
        print(f"{args.env}: found {len(msgs)} issue(s):")
        for m in msgs:
            print(f"  - {m}")


def cmd_compare(args):
    cfg_a = load_env(args.env_a)
    cfg_b = load_env(args.env_b)

    def summarize(cfg):
        g = AttackGraph(cfg["assets"], cfg["start_nodes"], cfg["goal_nodes"], cfg["edges"])
        paths = g.enumerate_paths(max_depth=args.max_depth)
        ranked = rank_paths(paths, top_k=args.top_k)
        total_eloss = sum(r["expected_loss"] for r in ranked)
        max_eloss = max((r["expected_loss"] for r in ranked), default=0.0)
        return total_eloss, max_eloss, ranked

    total_a, max_a, ranked_a = summarize(cfg_a)
    total_b, max_b, ranked_b = summarize(cfg_b)

    print("Environment Comparison")
    print(f"Top-K = {args.top_k}, max_depth = {args.max_depth}")
    print()
    print(f"Env A: {args.env_a}")
    print(f"  Sum E[L] top-K: {total_a:.2f}")
    print(f"  Max E[L] path : {max_a:.2f}")
    print()
    print(f"Env B: {args.env_b}")
    print(f"  Sum E[L] top-K: {total_b:.2f}")
    print(f"  Max E[L] path : {max_b:.2f}")
    print()

    delta_sum = total_b - total_a
    delta_max = max_b - max_a
    print("Δ (B − A):")
    print(f"  Δ Sum E[L]: {delta_sum:+.2f}")
    print(f"  Δ Max E[L]: {delta_max:+.2f}")
    print()
    print("Top paths in Env A:")
    print_path_table(ranked_a)
    print()
    print("Top paths in Env B:")
    print_path_table(ranked_b)


def build_arg_parser():
    ap = argparse.ArgumentParser(description="Attack-path planner and risk analytics CLI")
    sub = ap.add_subparsers(dest="command", required=True)

    # plan
    ap_plan = sub.add_parser("plan")
    ap_plan.add_argument("--env", default="data/env.yaml")
    ap_plan.add_argument("--max-depth", type=int, default=5)
    ap_plan.add_argument("--top-k", type=int, default=5)
    ap_plan.add_argument("--wI", type=float, default=1.0)
    ap_plan.add_argument("--wD", type=float, default=0.5)
    ap_plan.add_argument("--wT", type=float, default=0.1)
    ap_plan.add_argument("--wP", type=float, default=1.0)
    ap_plan.add_argument("--json-out")
    ap_plan.add_argument("--explain", type=int, default=0)
    ap_plan.set_defaults(func=cmd_plan)

    # edges
    ap_edges = sub.add_parser(
        "edges", help="Show edges with highest aggregated expected-loss contribution"
    )
    ap_edges.add_argument("--env", default="data/env.yaml")
    ap_edges.add_argument("--max-depth", type=int, default=5)
    ap_edges.add_argument("--top-k", type=int, default=10)
    ap_edges.add_argument("--limit", type=int, default=15)
    ap_edges.add_argument("--mitigations", type=int, default=5)
    ap_edges.set_defaults(func=cmd_edges)

    # validate
    ap_val = sub.add_parser("validate")
    ap_val.add_argument("--env", default="data/env.yaml")
    ap_val.set_defaults(func=cmd_validate)

    # compare
    ap_cmp = sub.add_parser(
        "compare", help="Compare baseline and hardened on expected loss"
    )
    ap_cmp.add_argument("--env-a", required=True)
    ap_cmp.add_argument("--env-b", required=True)
    ap_cmp.add_argument("--max-depth", type=int, default=5)
    ap_cmp.add_argument("--top-k", type=int, default=5)
    ap_cmp.set_defaults(func=cmd_compare)

    return ap

def build_report(cfg, max_depth, top_k, wI, wD, wT, wP):
    g = AttackGraph(cfg["assets"], cfg["start_nodes"], cfg["goal_nodes"], cfg["edges"])
    paths = g.enumerate_paths(max_depth=max_depth)
    ranked = rank_paths(
        paths,
        wI=wI,
        wD=wD,
        wT=wT,
        wP=wP,
        top_k=top_k,
    )
    if getattr(args, "explain", 0) > 0:
    print()
    print(f"Detailed explanation for top {args.explain} path(s):")
    print("-" * 70)
    for i, entry in enumerate(ranked[: args.explain], 1):
        print(explain_path(entry, idx=i))
        print("-" * 70)

    # edge-level risk contributions
    edge_contrib = edge_risk_contributions(ranked)
    edges_report = []
    for (src, dst, tech), score in edge_contrib.items():
        edges_report.append({
            "src": src,
            "dst": dst,
            "technique": tech,
            "expected_loss_contribution": score,
        })

    # path-level report
    paths_report = []
    for idx, r in enumerate(ranked, 1):
        steps = []
        for e in r["path"]:
            steps.append({
                "src": e.get("src"),
                "dst": e.get("dst"),
                "technique": e.get("technique"),
                "p": float(e.get("p", 0.5)),
                "impact": float(e.get("impact", 1.0)),
                "detect": float(e.get("detect", 0.3)),
                "time": float(e.get("time", 1.0)),
            })
        paths_report.append({
            "rank": idx,
            "utility": r["utility"],
            "probability": r["prob"],
            "impact": r["impact"],
            "detect": r["detect"],
            "time": r["time"],
            "expected_loss": r["expected_loss"],
            "steps": steps,
        })

    report = {
        "environment": {
            "assets": cfg.get("assets", []),
            "start_nodes": cfg.get("start_nodes", []),
            "goal_nodes": cfg.get("goal_nodes", []),
        },
        "parameters": {
            "max_depth": max_depth,
            "top_k": top_k,
            "weights": {
                "wI": wI,
                "wD": wD,
                "wT": wT,
                "wP": wP,
            },
        },
        "paths": paths_report,
        "edge_risk_contributions": edges_report,
    }
    return report


def main():
    ap = build_arg_parser()
    args = ap.parse_args()
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

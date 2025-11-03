import argparse, json
from pathlib import Path
try:
    import yaml  # installed via requirements.txt
except ImportError:
    yaml = None

from graph import AttackGraph
from planner import rank_paths

def load_env(path: str):
    p = Path(path)
    if p.suffix.lower() in (".yaml", ".yml") and yaml:
        return yaml.safe_load(p.read_text())
    return json.loads(p.read_text())

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--env", default="data/env.yaml")
    ap.add_argument("--max-depth", type=int, default=4)
    ap.add_argument("--top-k", type=int, default=5)
    ap.add_argument("--wI", type=float, default=1.0)
    ap.add_argument("--wD", type=float, default=0.5)
    ap.add_argument("--wT", type=float, default=0.1)
    ap.add_argument("--wP", type=float, default=1.0)
    a = ap.parse_args()

    cfg = load_env(a.env)
    g = AttackGraph(cfg["assets"], cfg["start_nodes"], cfg["goal_nodes"], cfg["edges"])
    paths = g.enumerate_paths(max_depth=a.max_depth)
    ranked = rank_paths(paths, wI=a.wI, wD=a.wD, wT=a.wT, wP=a.wP, top_k=a.top_k)

    for i, r in enumerate(ranked, 1):
        steps = " -> ".join(e.get("technique", "?") for e in r["path"])
        print(f"[{i}] U={r['utility']:.3f}  P={r['prob']:.3f}  I={r['impact']:.2f}  D={r['detect']:.2f}  T={r['time']:.2f}")
        print(f"    {steps}")

if __name__ == "__main__":
    main()


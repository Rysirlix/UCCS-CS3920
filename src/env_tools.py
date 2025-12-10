#!/usr/bin/env python3
import json
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None


def load_env(path="data/env.yaml"):
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError("Environment file not found: %s" % path)

    suffix = p.suffix.lower()
    text = p.read_text()

    if suffix in (".yaml", ".yml"):
        if not yaml:
            raise RuntimeError(
                "PyYAML not installed but a YAML file was requested: %s" % path
            )
        return yaml.safe_load(text)

    if suffix == ".json":
        return json.loads(text)

    if yaml:
        try:
            return yaml.safe_load(text)
        except Exception:
            pass

    return json.loads(text)


def save_env(cfg, path="data/env.yaml"):
    p = Path(path)
    suffix = p.suffix.lower()

    if suffix in (".yaml", ".yml"):
        if not yaml:
            raise RuntimeError(
                "PyYAML not installed but saving YAML was requested: %s" % path
            )
        data = yaml.safe_dump(cfg, default_flow_style=False, sort_keys=False)
        p.write_text(data)
        return

    data = json.dumps(cfg, indent=2)
    p.write_text(data)


def validate_env(cfg):
    errors = []

    required_top = ["assets", "start_nodes", "goal_nodes", "edges"]
    for key in required_top:
        if key not in cfg:
            errors.append("Missing top-level key: %s" % key)

    edges = cfg.get("edges", [])
    if not isinstance(edges, list):
        errors.append("'edges' must be a list")
        return errors

    for i, e in enumerate(edges):
        if "src" not in e or "dst" not in e:
            errors.append("Edge %d missing 'src' or 'dst'" % i)

    return errors


def summarize_env(cfg):
    assets = cfg.get("assets", [])
    starts = cfg.get("start_nodes", [])
    goals = cfg.get("goal_nodes", [])
    edges = cfg.get("edges", [])

    lines = []
    lines.append("Assets: %d" % len(assets))
    lines.append("Start nodes: %d -> %s" % (len(starts), ", ".join(map(str, starts))))
    lines.append("Goal nodes:  %d -> %s" % (len(goals), ", ".join(map(str, goals))))
    lines.append("Edges: %d" % len(edges))
    return "\n".join(lines)


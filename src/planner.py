
from models import (utility, path_success_probability, path_impact, path_detectability,path_time,)


def rank_paths(paths, *, wI=1.0, wD=0.5, wT=0.1, wP=1.0, top_k=5):
    scored = []
    for p in paths:
        prob = path_success_probability(p)
        impact = path_impact(p)
        detect = path_detectability(p)
        total_time = path_time(p)
        scored.append({
            "utility": utility(p, wI=wI, wD=wD, wT=wT, wP=wP),
            "prob": prob,
            "impact": impact,
            "detect": detect,
            "time": total_time,
            "expected_loss": prob * impact,
            "path": p,
        })

    scored.sort(key=lambda x: x["utility"], reverse=True)
    return scored[:top_k]


def edge_risk_contributions(ranked_paths):
    edge_scores = {}

    for entry in ranked_paths:
        prob = entry.get("prob", 0.0)
        impact = entry.get("impact", 0.0)
        path = entry.get("path", [])
        if not path:
            continue

        per_edge = (prob * impact) / len(path)

        for edge in path:
            key = (
                edge.get("src"),
                edge.get("dst"),
                edge.get("technique"),
            )
            edge_scores[key] = edge_scores.get(key, 0.0) + per_edge

    return edge_scores


MITIGATION_LIBRARY = {
    "T1566": "Phishing: user training, phishing-resistant MFA, email filtering.",
    "T1059": "Command & Scripting: application allowlisting, script blocking, EDR.",
    "T1068": "Privilege Escalation: timely patching, least privilege, EDR on endpoints.",
    "T1021": "Remote Services: strong auth, network segmentation, logging & alerts.",
    "T1041": "Exfiltration Over C2: egress filtering, DLP, anomaly-based traffic monitoring.",
    "T1078": "Valid Accounts: MFA, credential hygiene, disable dormant accounts.",
}

def _extract_tech_id(tech_string):
    if not tech_string:
        return "UNKNOWN"
    parts = tech_string.split()
    first = parts[0]
    if first.startswith("T") and any(c.isdigit() for c in first):
        return first
    return "UNKNOWN"

def suggest_mitigations(edge_scores, limit=5):
    by_tech = {}

    for (src, dst, tech), score in edge_scores.items():
        tech_id = _extract_tech_id(tech)
        entry = by_tech.get(tech_id)
        if not entry:
            entry = {
                "tech_id": tech_id,
                "total_expected_loss": 0.0,
                "examples": [],
            }
            by_tech[tech_id] = entry

        entry["total_expected_loss"] += score
        if len(entry["examples"]) < 3:
            entry["examples"].append(
                {
                    "src": src,
                    "dst": dst,
                    "technique": tech,
                    "edge_expected_loss": score,
                }
            )

    ranked = sorted(
        by_tech.values(),
        key=lambda e: e["total_expected_loss"],
        reverse=True,
    )

    results = []
    for entry in ranked[:limit]:
        tech_id = entry["tech_id"]
        mitigation = MITIGATION_LIBRARY.get(
            tech_id,
            "General hardening: patching, least privilege, logging, and segmentation.",
        )
        results.append(
            {
                "tech_id": tech_id,
                "total_expected_loss": entry["total_expected_loss"],
                "mitigation": mitigation,
                "examples": entry["examples"],
            }
        )

    return results

def explain_path(path_entry, idx=1):
    lines = []
    lines.append(f"Path {idx}:")
    lines.append(
        f"  Utility={path_entry.get('utility', 0):.3f}, "
        f"P_success={path_entry.get('prob', 0):.3f}, "
        f"Impact={path_entry.get('impact', 0):.2f}, "
        f"Detect={path_entry.get('detect', 0):.2f}, "
        f"Time={path_entry.get('time', 0):.2f}, "
        f"E[L]={path_entry.get('expected_loss', 0):.2f}"
    )

    steps = path_entry.get("path", [])
    if not steps:
        lines.append("  (no steps)")
        return "\n".join(lines)

    lines.append("  Steps:")
    for i, edge in enumerate(steps, 1):
        src = edge.get("src", "?")
        dst = edge.get("dst", "?")
        tech = edge.get("technique", "?")
        p = edge.get("p", 0.0)
        impact = edge.get("impact", 0.0)
        detect = edge.get("detect", 0.0)
        t = edge.get("time", 0.0)

        lines.append(
            f"    {i}. {src} -> {dst} "
            f"via {tech} "
            f"(p={p:.2f}, impact={impact:.1f}, "
            f"detect={detect:.2f}, time={t:.2f})"
        )

    return "\n".join(lines)

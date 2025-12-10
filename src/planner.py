
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

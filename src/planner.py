from typing import List, Dict, Any
from models import utility, path_success_probability, path_impact, path_detectability, path_time

def rank_paths(paths: List[List[Dict[str, Any]]], *, wI=1.0, wD=0.5, wT=0.1, wP=1.0, top_k=5):
    scored = []
    for p in paths:
        scored.append({
            "utility": utility(p, wI=wI, wD=wD, wT=wT, wP=wP),
            "prob": path_success_probability(p),
            "impact": path_impact(p),
            "detect": path_detectability(p),
            "time": path_time(p),
            "path": p
        })
    scored.sort(key=lambda x: x["utility"], reverse=True)
    return scored[:top_k]


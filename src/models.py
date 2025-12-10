import math

def path_success_probability(path):
    p = 1.0
    for e in path:
        p *= max(0.0, min(1.0, float(e.get("p", 0.5))))
    return p

def path_impact(path):
    return sum(float(e.get("impact", 1.0)) for e in path)

def path_detectability(path):
    return sum(float(e.get("detect", 0.3)) for e in path)

def path_time(path):
    return sum(float(e.get("time", 1.0)) for e in path)

def utility(path, wI=1.0, wD=0.5, wT=0.1, wP=1.0):
    """wI*Impact + wP*log(P) − wD*Detect − wT*Time"""
    P = max(1e-9, path_success_probability(path))
    I = path_impact(path)
    D = path_detectability(path)
    T = path_time(path)
    return wI * I + wP * math.log(P) - wD * D - wT * T

def expected_loss(path):
    """E[L] = P(success) * Impact"""
    P = path_success_probability(path)
    I = path_impact(path)
    return P * I
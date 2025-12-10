from graph import AttackGraph
from caldera_integration import CalderaClient

def system_to_attack_graph(system_config: Dict, 
                           caldera_client: CalderaClient) -> AttackGraph:
    """
    Convert user system description + Caldera abilities 
    into an attack graph
    """
    assets = []
    start_nodes = []
    goal_nodes = []
    edges = []
    
    # Extract assets from system config
    for subnet in system_config["network"]["subnets"]:
        if "hosts" in subnet:
            for host in subnet["hosts"]:
                assets.append(host["name"])
                if host.get("critical"):
                    goal_nodes.append(host["name"])
        else:
            # Generic subnet representation
            assets.append(subnet["name"])
    
    # Map access points to start nodes
    for ap in system_config.get("access_points", []):
        start_nodes.append(f"{ap['type']}_entry")
    
    # Get Caldera abilities and map to edges
    abilities = caldera_client.get_abilities()
    
    # Map vulnerabilities to attack edges
    for vuln in system_config.get("vulnerabilities", []):
        for target in vuln["affects"]:
            # Find relevant Caldera abilities for this CVE
            matching_abilities = find_abilities_for_vuln(vuln, abilities)
            for ability in matching_abilities:
                edges.append({
                    "src": determine_source(target, assets),
                    "dst": target,
                    "technique": ability["tactic"],
                    "p": estimate_success_rate(vuln["severity"]),
                    "impact": calculate_impact(target, system_config),
                    "detect": ability.get("detectability", 0.5),
                    "time": ability.get("execution_time", 1.0)
                })
    
    return AttackGraph(assets, start_nodes, goal_nodes, edges)

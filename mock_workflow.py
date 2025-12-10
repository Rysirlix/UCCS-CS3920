#!/usr/bin/env python3
"""
mock_workflow.py - FIXED VERSION
Complete workflow for Mock plugin integration with proper authentication
"""

import argparse
import sys
from pathlib import Path
import yaml
import json

# Add src to path
src_dir = Path(__file__).resolve().parent / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from mock_environment import MockEnvironmentManager, load_system_config
from caldera_integration import CalderaClient  # FIXED: Import CalderaClient directly
from graph import AttackGraph
from planner import rank_paths, edge_risk_contributions


class MockWorkflowOrchestrator:
    """
    Orchestrates the complete workflow for mock-based attack testing:
    1. Load user system config
    2. Generate mock agents
    3. Build attack graph
    4. Execute ranked paths in mock environment
    5. Update graph based on results
    """
    
    def __init__(self, system_config_path: str, caldera_url: str = "http://localhost:8888",
                 caldera_path: str = None, api_key: str = "ADMIN123"):  # FIXED: Default key
        self.system_config_path = system_config_path
        self.caldera_url = caldera_url
        self.caldera_path = caldera_path
        self.api_key = api_key  # FIXED: Use provided key
        
        self.system_config = None
        self.mock_manager = None
        self.caldera_client = None
        self.attack_graph = None
        self.ranked_paths = None
    
    def run_complete_workflow(self, execute_top_n: int = 0):
        """
        Execute the complete workflow
        
        Args:
            execute_top_n: Number of top-ranked paths to execute (0 = don't execute)
        """
        print("\n" + "="*70)
        print(" MOCK-BASED ATTACK GRAPH TESTING WORKFLOW")
        print("="*70 + "\n")
        
        # Step 1: Load system configuration
        print("[Step 1/7] Loading system configuration...")
        self.system_config = load_system_config(self.system_config_path)
        print(f"  ✓ Loaded config for: {self.system_config.get('network', {}).get('name')}")
        
        # Step 2: Generate mock environment
        print("\n[Step 2/7] Generating mock environment...")
        self.mock_manager = MockEnvironmentManager(caldera_path=self.caldera_path)
        agents = self.mock_manager.create_agents_from_system_config(self.system_config)
        print(f"  ✓ Created {len(agents)} mock agents")
        
        # Step 3: Write mock files to Caldera
        print("\n[Step 3/7] Writing mock configuration files...")
        paths = self.mock_manager.create_full_mock_environment(
            self.system_config,
            self.caldera_path
        )
        print(f"  ✓ Generated files:")
        print(f"    - {paths.get('agents', 'mock_agents.yml')}")
        print(f"    - {paths.get('responses', 'mock_responses.yml')}")
        
        # IMPORTANT: Remind user about file placement
        if not self.caldera_path:
            print("\n  ⚠ IMPORTANT: Copy these files to Caldera:")
            print(f"    cp mock_agents.yml <caldera>/plugins/mock/conf/agents.yml")
            print(f"    cp mock_responses.yml <caldera>/plugins/mock/conf/scenarios/")
            print(f"  Then restart Caldera before executing paths!")
        
        # Step 4: Build attack graph
        print("\n[Step 4/7] Building attack graph from system topology...")
        graph_config = self._build_attack_graph_config()
        self.attack_graph = AttackGraph(
            graph_config["assets"],
            graph_config["start_nodes"],
            graph_config["goal_nodes"],
            graph_config["edges"]
        )
        all_paths = self.attack_graph.enumerate_paths(max_depth=5)
        print(f"  ✓ Found {len(all_paths)} possible attack paths")
        
        # Step 5: Rank attack paths
        print("\n[Step 5/7] Ranking attack paths by utility...")
        self.ranked_paths = rank_paths(all_paths, top_k=10)
        print(f"  ✓ Ranked top 10 paths")
        self._display_ranked_paths()
        self._display_edge_risk_summary(top_n=10)
        
        # Step 6: Connect to Caldera (optional)
        if execute_top_n > 0:
            print("\n[Step 6/7] Connecting to Caldera mock environment...")
            
            # FIXED: Create client with proper authentication and simulation mode
            self.caldera_client = CalderaClient(
                base_url=self.caldera_url,
                api_key=self.api_key,
                simulation_mode=True  # This tells it to look for 'simulation' group
            )
            
            # Test connection
            print(f"  → Testing connection to {self.caldera_url}...")
            if not self.caldera_client.test_connection():
                print("  ✗ Cannot connect to Caldera")
                print("\n  Troubleshooting:")
                print("  1. Is Caldera running?")
                print("     → cd <caldera> && python server.py --insecure")
                print("  2. Is mock plugin enabled in conf/local.yml?")
                print("     → plugins: ['mock', 'stockpile']")
                print("  3. Did you copy the agent files?")
                print("     → See Step 3 output above")
                print("\n  Run diagnostics:")
                print(f"     python caldera_diagnostic.py --url {self.caldera_url}")
                return False
            
            print(f"  ✓ Connected to Caldera at {self.caldera_url}")
            
            # Verify mock agents
            print(f"  → Discovering mock agents in 'simulation' group...")
            mock_agents = self.caldera_client.discover_agents(group="simulation")
            
            if not mock_agents:
                print("  ✗ No mock agents found in 'simulation' group!")
                print("\n  This means:")
                print("  1. Mock plugin may not be loaded")
                print("  2. Agents file not in correct location")
                print("  3. No agents have enabled: True")
                print("\n  Check Caldera UI → Agents tab")
                print("  You should see your simulated agents there")
                
                # Try any group as fallback
                all_agents = self.caldera_client.discover_agents()
                if all_agents:
                    print(f"\n  ℹ Found {len(all_agents)} agents in other groups:")
                    for agent in all_agents[:5]:
                        print(f"    - {agent.get('paw')}: {agent.get('host')} (group: {agent.get('group')})")
                    
                    use_anyway = input("\n  Use these agents anyway? (y/n): ")
                    if use_anyway.lower() != 'y':
                        return False
                    mock_agents = all_agents
                else:
                    print("\n  ✗ No agents available at all!")
                    return False
            else:
                print(f"  ✓ Found {len(mock_agents)} mock agents ready:")
                for agent in mock_agents[:5]:
                    print(f"    - PAW: {agent.get('paw')}, Host: {agent.get('host')}, "
                          f"Platform: {agent.get('platform')}, Privilege: {agent.get('privilege')}")
            
            # Step 7: Execute paths
            print(f"\n[Step 7/7] Executing top {execute_top_n} attack paths...")
            self._execute_paths(execute_top_n, mock_agents)
        else:
            print("\n[Step 6/7] Skipping Caldera connection (not executing paths)")
            print("[Step 7/7] Skipping path execution")
        
        print("\n" + "="*70)
        print(" WORKFLOW COMPLETE")
        print("="*70)
        print("\nNext steps:")
        if execute_top_n == 0:
            print("  1. Ensure mock plugin files are in place (see Step 3 above)")
            print("  2. Start/restart Caldera: cd <caldera> && python server.py --insecure")
            print("  3. Verify agents in UI: http://localhost:8888 → Agents tab")
            print(f"  4. Re-run with --execute 3 to test paths")
            print(f"  5. Or view visualization: python src/cli.py --visualize")
        else:
            print(f"  1. Review execution results above")
            print(f"  2. Check updated graph probabilities")
            print(f"  3. View in web UI: python src/cli.py --visualize")
            print(f"  4. Export report: add --export flag")
        print("="*70 + "\n")
        
        return True
    
    def _build_attack_graph_config(self) -> dict:
        """Build attack graph configuration from system config"""
        assets = []
        start_nodes = []
        goal_nodes = []
        edges = []
        
        # Extract assets
        for subnet in self.system_config.get("network", {}).get("subnets", []):
            if "hosts" in subnet:
                for host in subnet["hosts"]:
                    assets.append(host["name"])
                    if host.get("critical"):
                        goal_nodes.append(host["name"])
            elif "name" in subnet:
                assets.append(subnet["name"])
        
        # Add high-value targets as goals
        for target in self.system_config.get("high_value_targets", []):
            target_name = target["name"]
            if target_name not in goal_nodes:
                goal_nodes.append(target_name)
            if target_name not in assets:
                assets.append(target_name)
        
        # Add start nodes from access points
        for access_point in self.system_config.get("access_points", []):
            start_node = f"{access_point['type']}_entry"
            start_nodes.append(start_node)
            assets.append(start_node)
        
        # Build edges from access points
        for access_point in self.system_config.get("access_points", []):
            source = f"{access_point['type']}_entry"
            
            if "target_host" in access_point:
                target = access_point["target_host"]
            elif "target_subnet" in access_point:
                target = access_point["target_subnet"]
            else:
                continue
            
            edges.append({
                "src": source,
                "dst": target,
                "technique": f"T1566 {access_point['type'].title()}",
                "p": access_point.get("success_rate", 0.3),
                "impact": 1.0,
                "detect": access_point.get("detection_rate", 0.3),
                "time": 1.0
            })
        
        # Build edges from vulnerabilities
        for vuln in self.system_config.get("vulnerabilities", []):
            for target in vuln.get("affects", []):
                if target in assets:
                    source = "user_workstations"
                    
                    edges.append({
                        "src": source,
                        "dst": target,
                        "technique": f"T1068 Exploit {vuln['cve']}",
                        "p": 0.7 if vuln.get("exploitable") else 0.3,
                        "impact": 5.0 if vuln.get("severity") == "critical" else 3.0,
                        "detect": 0.6 if vuln.get("severity") == "critical" else 0.4,
                        "time": 2.0
                    })
        
        # Add lateral movement edges
        if "user_workstations" in assets:
            for asset in assets:
                if asset != "user_workstations" and "entry" not in asset:
                    edges.append({
                        "src": "user_workstations",
                        "dst": asset,
                        "technique": "T1021 Remote Services",
                        "p": 0.4,
                        "impact": 2.0,
                        "detect": 0.5,
                        "time": 1.5
                    })
        
        # Add data exfiltration edges
        for subnet in self.system_config.get("network", {}).get("subnets", []):
            if "hosts" in subnet:
                for host in subnet["hosts"]:
                    if host.get("critical") and host.get("data_classification"):
                        exfil_node = f"exfiltrated_{host['name']}_data"
                        assets.append(exfil_node)
                        goal_nodes.append(exfil_node)
                        
                        edges.append({
                            "src": host["name"],
                            "dst": exfil_node,
                            "technique": "T1041 Exfiltration Over C2",
                            "p": 0.6,
                            "impact": 8.0 if host["data_classification"] == "restricted" else 5.0,
                            "detect": 0.7,
                            "time": 2.0
                        })
        
        return {
            "assets": assets,
            "start_nodes": start_nodes,
            "goal_nodes": goal_nodes,
            "edges": edges
        }
    
    def _display_ranked_paths(self):
        if not self.ranked_paths:
            print("\n  No attack paths found.")
            return

        print("\n  Top Attack Paths (computed by models.py / planner.py):")
        print("  " + "-" * 90)
        print("  Rank  U        Psucc    Impact   Detect    Time    E[L]    Steps")
        print("  " + "-" * 90)

        for i, path in enumerate(self.ranked_paths[:5], 1):
            techniques = " → ".join(e.get("technique", "?") for e in path["path"])
            print(
                "  [{idx}] U={u:6.3f} | P={p:.3f} | I={I:4.1f} | "
                "D={D:.2f} | T={T:4.2f} | E[L]={L:6.2f}".format(
                    idx=i,
                    u=path["utility"],
                    p=path["prob"],
                    I=path["impact"],
                    D=path["detect"],
                    T=path["time"],
                    L=path.get("expected_loss", path["prob"] * path["impact"]),
                )
            )
            print("       ", techniques[:70], "..." if len(techniques) > 70 else "")
        print("  " + "-" * 90)
    
    def _display_edge_risk_summary(self, top_n=10):
        if not self.ranked_paths:
            return

        scores = edge_risk_contributions(self.ranked_paths)
        if not scores:
            return

        items = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)

        print("\n  Edge Risk Contributions (from planner.edge_risk_contributions):")
        print("  " + "-" * 100)
        print("  Rank  Src                 Dst                      Technique                         E[L] contrib")
        print("  " + "-" * 100)

        for i, (key, value) in enumerate(items[:top_n], 1):
            src, dst, tech = key
            print(
                "  {idx:<4}  {src:<18}  {dst:<24}  {tech:<30}  {score:10.2f}".format(
                    idx=i,
                    src=str(src),
                    dst=str(dst),
                    tech=str(tech),
                    score=value,
                )
            )
        print("  " + "-" * 100)

    def _execute_paths(self, top_n: int, agents: list):
        """Execute top N paths in mock environment"""
        agent_paws = [a["paw"] for a in agents]
        
        if not agent_paws:
            print("  ✗ No agents available!")
            return
        
        execution_results = []
        
        for i in range(min(top_n, len(self.ranked_paths))):
            path = self.ranked_paths[i]
            print(f"\n  Executing path {i+1}/{top_n}...")
            print(f"  Path: {' → '.join(e.get('technique', '?') for e in path['path'])}")
            
            result = self.caldera_client.execute_attack_path(
                path["path"],
                f"Mock_Test_Path_{i+1}",
                agent_paws
            )
            
            execution_results.append(result)
            
            # Update graph based on results
            if not result.get("error"):
                self._update_graph_from_execution(result)
        
        # Display summary
        self._display_execution_summary(execution_results)
    
    def _update_graph_from_execution(self, execution_result: dict):
        """Update graph probabilities based on execution results"""
        for result in execution_result.get("results", []):
            technique = result.get("step")
            status = result.get("status")
            
            # Find matching edges
            for edge in self.attack_graph.edges:
                if edge.get("technique") == technique:
                    old_p = edge.get("p", 0.5)
                    
                    # Update probability
                    if status == "success":
                        edge["p"] = min(1.0, old_p * 1.2)
                        print(f"    ✓ Updated {technique}: p {old_p:.3f} → {edge['p']:.3f}")
                    elif status == "failed":
                        edge["p"] = max(0.0, old_p * 0.5)
                        print(f"    ✗ Updated {technique}: p {old_p:.3f} → {edge['p']:.3f}")
                    
                    # Update detectability
                    if result.get("detected"):
                        old_detect = edge.get("detect", 0.3)
                        edge["detect"] = min(1.0, old_detect * 1.3)
                        print(f"    🔴 Detection increased: {old_detect:.3f} → {edge['detect']:.3f}")
    
    def _display_execution_summary(self, results: list):
        """Display summary of execution results"""
        print("\n  " + "="*66)
        print("  EXECUTION SUMMARY")
        print("  " + "="*66)
        
        total_steps = sum(r.get("total_steps", 0) for r in results)
        completed_steps = sum(r.get("completed_steps", 0) for r in results)
        successful_steps = sum(
            sum(1 for res in r.get("results", []) if res.get("status") == "success")
            for r in results
        )
        detected_steps = sum(
            sum(1 for res in r.get("results", []) if res.get("detected"))
            for r in results
        )
        
        print(f"  Total Paths Attempted: {len(results)}")
        print(f"  Total Steps: {total_steps}")
        print(f"  Completed Steps: {completed_steps} ({completed_steps/total_steps*100 if total_steps > 0 else 0:.1f}%)")
        print(f"  Successful Steps: {successful_steps}")
        print(f"  Detected Steps: {detected_steps} ({detected_steps/completed_steps*100 if completed_steps > 0 else 0:.1f}%)")
        print("  " + "="*66)
    
    def export_results(self, output_dir="results"):
        """Export results to files"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)

        # Export updated graph
        graph_config = {
            "assets": list(self.attack_graph.assets),
            "start_nodes": list(self.attack_graph.start_nodes),
            "goal_nodes": list(self.attack_graph.goal_nodes),
            "edges": self.attack_graph.edges,
        }

        with open(output_path / "updated_graph.yaml", "w") as f:
            yaml.dump(graph_config, f, default_flow_style=False)

        # Export ranked paths
        paths_export = []
        for i, path in enumerate(self.ranked_paths, 1):
            paths_export.append({
                "rank": i,
                "utility": path["utility"],
                "probability": path["prob"],
                "impact": path["impact"],
                "detectability": path["detect"],
                "time": path["time"],
                "expected_loss": path.get("expected_loss", path["prob"] * path["impact"]),
                "steps": [e.get("technique") for e in path["path"]],
            })

        with open(output_path / "ranked_paths.json", "w") as f:
            json.dump(paths_export, f, indent=2)

        # Export edge risk contributions
        edge_scores = edge_risk_contributions(self.ranked_paths)
        edge_export = []
        for (src, dst, tech), score in sorted(
            edge_scores.items(), key=lambda kv: kv[1], reverse=True
        ):
            edge_export.append({
                "src": src,
                "dst": dst,
                "technique": tech,
                "expected_loss_contribution": score,
            })

        with open(output_path / "edge_risks.json", "w") as f:
            json.dump(edge_export, f, indent=2)

        print("\n✓ Results exported to {}".format(output_path))
        print("  - updated_graph.yaml")
        print("  - ranked_paths.json (includes expected_loss from models/planner)")
        print("  - edge_risks.json (edge risk contributions from planner.edge_risk_contributions)")


def main():
    parser = argparse.ArgumentParser(
        description="Mock-based Attack Graph Testing Workflow",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate mock environment only
  python mock_workflow.py --system-config data/system_template.yaml

  # Generate and execute top 3 paths
  python mock_workflow.py --system-config data/system_template.yaml --execute 3

  # With custom Caldera settings
  python mock_workflow.py --system-config data/my_network.yaml \\
      --caldera-path /opt/caldera \\
      --caldera-url http://192.168.1.100:8888 \\
      --caldera-key MYKEY123 \\
      --execute 5
        """
    )
    
    parser.add_argument(
        "--system-config",
        required=True,
        help="Path to system topology YAML file"
    )
    parser.add_argument(
        "--caldera-path",
        help="Path to Caldera installation (to write files directly)"
    )
    parser.add_argument(
        "--caldera-url",
        default="http://localhost:8888",
        help="Caldera server URL (default: http://localhost:8888)"
    )
    parser.add_argument(
        "--caldera-key",
        default="ADMIN123",  # FIXED: Correct default
        help="Caldera API key (default: ADMIN123)"
    )
    parser.add_argument(
        "--execute",
        type=int,
        default=0,
        metavar="N",
        help="Execute top N ranked paths in mock environment"
    )
    parser.add_argument(
        "--export",
        action="store_true",
        help="Export results to files"
    )
    
    args = parser.parse_args()
    
    # Run workflow
    orchestrator = MockWorkflowOrchestrator(
        system_config_path=args.system_config,
        caldera_url=args.caldera_url,
        caldera_path=args.caldera_path,
        api_key=args.caldera_key
    )
    
    success = orchestrator.run_complete_workflow(execute_top_n=args.execute)
    
    if success and args.export:
        orchestrator.export_results()
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
mock_environment.py - Integrate Caldera Mock Plugin
Automatically generates mock agents from system topology
and manages simulated attack execution for safe testing
"""

import yaml
import json
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass, asdict


@dataclass
class MockAgent:
    """Represents a simulated Caldera agent"""
    paw: str
    username: str
    host: str
    group: str
    platform: str
    location: str
    enabled: bool
    privilege: str
    c2: str
    exe_name: str
    executors: List[str]


class MockEnvironmentManager:
    """
    Manages creation and configuration of Mock plugin agents
    based on user system topology
    """
    
    def __init__(self, caldera_path: str = None):
        """
        Initialize the mock environment manager
        
        Args:
            caldera_path: Path to Caldera installation (to write conf/agents.yml)
        """
        self.caldera_path = Path(caldera_path) if caldera_path else None
        self.mock_agents = []
        self.vulnerability_responses = {}
    
    def create_agents_from_system_config(self, system_config: Dict) -> List[MockAgent]:
        """
        Generate mock agents from system topology configuration
        
        Args:
            system_config: User's system configuration from system_template.yaml
            
        Returns:
            List of MockAgent objects representing the network
        """
        agents = []
        agent_id = 1000
        
        # Process each subnet/network segment
        for subnet in system_config.get("network", {}).get("subnets", []):
            
            # Handle individual hosts
            if "hosts" in subnet:
                for host in subnet["hosts"]:
                    agent = self._create_agent_from_host(host, agent_id, subnet)
                    agents.append(agent)
                    agent_id += 1
            
            # Handle bulk workstation subnets
            elif "count" in subnet:
                for i in range(subnet["count"]):
                    host_def = {
                        "name": f"{subnet['name']}_{i+1}",
                        "os": subnet["os"][i % len(subnet["os"])],
                        "services": subnet.get("services", []),
                        "privilege_level": "User"
                    }
                    agent = self._create_agent_from_host(host_def, agent_id, subnet)
                    agents.append(agent)
                    agent_id += 1
        
        self.mock_agents = agents
        return agents
    
    def _create_agent_from_host(self, host: Dict, agent_id: int, subnet: Dict) -> MockAgent:
        """Create a single mock agent from host definition"""
        platform = self._normalize_platform(host.get("os", "windows"))
        
        return MockAgent(
            paw=f"mock_{agent_id}",
            username=self._generate_username(host["name"]),
            host=host["name"],
            group="simulation",
            platform=platform,
            location=self._get_default_location(platform),
            enabled=True,
            privilege=host.get("privilege_level", "User"),
            c2="HTTP",
            exe_name="sandcat.exe" if platform == "windows" else "sandcat",
            executors=self._get_executors_for_platform(platform)
        )
    
    def _normalize_platform(self, os_name: str) -> str:
        """Normalize OS names to Caldera platform identifiers"""
        os_lower = os_name.lower()
        if "windows" in os_lower:
            return "windows"
        elif "linux" in os_lower:
            return "linux"
        elif "darwin" in os_lower or "macos" in os_lower:
            return "darwin"
        return "windows"  # default
    
    def _generate_username(self, hostname: str) -> str:
        """Generate plausible username from hostname"""
        if "admin" in hostname.lower() or "controller" in hostname.lower():
            return "administrator"
        elif "server" in hostname.lower():
            return "service_account"
        else:
            return "user"
    
    def _get_default_location(self, platform: str) -> str:
        """Get default installation location for platform"""
        locations = {
            "windows": "C:\\Users\\Public\\sandcat.exe",
            "linux": "/tmp/sandcat",
            "darwin": "/tmp/sandcat"
        }
        return locations.get(platform, locations["windows"])
    
    def _get_executors_for_platform(self, platform: str) -> List[str]:
        """Get available executors for platform"""
        executors = {
            "windows": ["pwsh", "psh", "cmd"],
            "linux": ["sh", "bash"],
            "darwin": ["sh", "bash"]
        }
        return executors.get(platform, executors["windows"])
    
    def generate_mock_responses(self, system_config: Dict) -> Dict[str, Any]:
        """
        Generate mock ability responses based on system vulnerabilities
        
        This tells the mock plugin how agents should respond to specific abilities
        """
        responses = {}
        
        # Process vulnerabilities to create realistic responses
        for vuln in system_config.get("vulnerabilities", []):
            cve = vuln.get("cve")
            affected_hosts = vuln.get("affects", [])
            severity = vuln.get("severity", "medium")
            
            # Create response definitions
            for host in affected_hosts:
                # Map CVE to likely ATT&CK techniques
                techniques = self._map_cve_to_techniques(cve)
                
                for technique in techniques:
                    response_key = f"{host}_{technique}"
                    responses[response_key] = {
                        "status": "success" if severity in ["high", "critical"] else "failed",
                        "output": self._generate_realistic_output(technique, cve, severity),
                        "pid": 1234,
                        "detected": severity == "critical"  # Critical vulns more likely detected
                    }
        
        self.vulnerability_responses = responses
        return responses
    
    def _map_cve_to_techniques(self, cve: str) -> List[str]:
        """Map CVE to likely ATT&CK technique IDs"""
        # Simplified mapping - in production, use CVE database
        cve_mappings = {
            "CVE-2021-1236": ["T1068"],  # Privilege Escalation
            "CVE-2021-34527": ["T1068", "T1212"],  # PrintNightmare
            "CVE-2020-1472": ["T1003", "T1558"],  # Zerologon
        }
        return cve_mappings.get(cve, ["T1059"])  # Default to command execution
    
    def _generate_realistic_output(self, technique: str, cve: str, severity: str) -> str:
        """Generate realistic command output for mock responses"""
        outputs = {
            "T1068": f"Privilege escalation successful using {cve}. Current user: SYSTEM",
            "T1003": f"Credentials dumped successfully. Found 15 user hashes.",
            "T1059": f"Command executed successfully.",
            "T1078": f"Valid credentials found. Access granted.",
            "T1041": f"Data exfiltrated: 1.5GB transferred to external host."
        }
        
        if severity == "critical":
            return outputs.get(technique, "Command executed with elevated privileges")
        elif severity == "high":
            return outputs.get(technique, "Command executed successfully")
        else:
            return "Insufficient privileges" if technique == "T1068" else "Command failed"
    
    def write_agents_yml(self, output_path: str = None):
        """
        Write mock agents to Caldera's conf/agents.yml file
        
        Args:
            output_path: Custom path to write agents.yml (defaults to caldera_path/conf/agents.yml)
        """
        if output_path:
            target_path = Path(output_path)
        elif self.caldera_path:
            target_path = self.caldera_path / "conf" / "agents.yml"
        else:
            target_path = Path("mock_agents.yml")
        
        # Convert agents to dict format
        agents_data = [asdict(agent) for agent in self.mock_agents]
        
        # Write to YAML
        target_path.parent.mkdir(parents=True, exist_ok=True)
        with open(target_path, 'w') as f:
            yaml.dump(agents_data, f, default_flow_style=False, sort_keys=False)
        
        print(f"✓ Written {len(self.mock_agents)} mock agents to {target_path}")
        return target_path
    
    def write_mock_responses(self, output_path: str = None):
        """
        Write mock responses to be used by mock plugin
        
        Args:
            output_path: Path to write mock_responses.yml
        """
        if output_path:
            target_path = Path(output_path)
        elif self.caldera_path:
            target_path = self.caldera_path / "plugins" / "mock" / "data" / "mock_responses.yml"
        else:
            target_path = Path("mock_responses.yml")
        
        target_path.parent.mkdir(parents=True, exist_ok=True)
        with open(target_path, 'w') as f:
            yaml.dump(self.vulnerability_responses, f)
        
        print(f"✓ Written mock responses to {target_path}")
        return target_path
    
    def generate_caldera_config(self) -> Dict[str, Any]:
        """
        Generate Caldera configuration snippet to enable mock plugin
        
        Returns:
            Dictionary with configuration to add to conf/local.yml
        """
        return {
            "plugins": ["mock", "stockpile", "sandcat"],
            "app.contact.http": "http://127.0.0.1:8888",
            "mock.enabled": True
        }
    
    def create_full_mock_environment(self, system_config: Dict, 
                                    caldera_path: str = None) -> Dict[str, Path]:
        """
        One-step creation of complete mock environment
        
        Args:
            system_config: System topology configuration
            caldera_path: Path to Caldera installation
            
        Returns:
            Dictionary with paths to generated files
        """
        self.caldera_path = Path(caldera_path) if caldera_path else self.caldera_path
        
        print("=" * 60)
        print("Creating Mock Environment for Attack Graph Testing")
        print("=" * 60)
        
        # Step 1: Create agents
        print("\n[1/4] Generating mock agents from system topology...")
        agents = self.create_agents_from_system_config(system_config)
        print(f"  ✓ Created {len(agents)} mock agents")
        
        # Step 2: Generate responses
        print("\n[2/4] Generating mock responses based on vulnerabilities...")
        responses = self.generate_mock_responses(system_config)
        print(f"  ✓ Created {len(responses)} mock response definitions")
        
        # Step 3: Write agents file
        print("\n[3/4] Writing agents.yml...")
        agents_path = self.write_agents_yml()
        
        # Step 4: Write responses file
        print("\n[4/4] Writing mock_responses.yml...")
        responses_path = self.write_mock_responses()
        
        print("\n" + "=" * 60)
        print("Mock Environment Ready!")
        print("=" * 60)
        print("\nNext steps:")
        print("1. Copy files to Caldera:")
        if caldera_path:
            print(f"   - Agents already in: {agents_path}")
            print(f"   - Responses already in: {responses_path}")
        else:
            print(f"   cp {agents_path} <caldera>/conf/agents.yml")
            print(f"   cp {responses_path} <caldera>/plugins/mock/data/")
        print("2. Enable mock plugin in conf/local.yml:")
        print("   plugins: ['mock', 'stockpile']")
        print("3. Restart Caldera server")
        print("4. Run your attack graph operations!")
        print("=" * 60)
        
        return {
            "agents": agents_path,
            "responses": responses_path
        }
    
    def export_to_attack_graph_format(self) -> Dict[str, Any]:
        """
        Export mock environment to format compatible with your attack graph
        
        Returns:
            Dictionary in env.yaml format with mock agents as assets
        """
        assets = [agent.host for agent in self.mock_agents]
        
        # Identify start and goal nodes
        start_nodes = ["phishing_lure"]  # Entry points
        goal_nodes = [
            agent.host for agent in self.mock_agents 
            if agent.privilege == "Elevated" or "admin" in agent.username.lower()
        ]
        
        # Create edges based on network topology
        edges = self._generate_edges_from_topology()
        
        return {
            "assets": assets,
            "start_nodes": start_nodes,
            "goal_nodes": goal_nodes,
            "edges": edges,
            "mock_mode": True
        }
    
    def _generate_edges_from_topology(self) -> List[Dict[str, Any]]:
        """Generate realistic attack edges between mock agents"""
        edges = []
        
        # Create edges between different privilege levels
        user_agents = [a for a in self.mock_agents if a.privilege == "User"]
        admin_agents = [a for a in self.mock_agents if a.privilege in ["Elevated", "Administrator"]]
        
        # Lateral movement edges
        for user in user_agents[:5]:  # Sample connections
            edges.append({
                "src": "phishing_lure",
                "dst": user.host,
                "technique": "T1566 Phishing",
                "p": 0.35,
                "impact": 1.0,
                "detect": 0.3,
                "time": 1.0
            })
        
        # Privilege escalation edges
        for user in user_agents[:3]:
            for admin in admin_agents[:2]:
                if user.platform == admin.platform:
                    edges.append({
                        "src": user.host,
                        "dst": admin.host,
                        "technique": "T1068 Privilege Escalation",
                        "p": 0.25,
                        "impact": 4.0,
                        "detect": 0.5,
                        "time": 2.0
                    })
        
        return edges


def load_system_config(path: str) -> Dict:
    """Load system configuration from YAML or JSON"""
    p = Path(path)
    if p.suffix.lower() in (".yaml", ".yml"):
        with open(p) as f:
            return yaml.safe_load(f)
    else:
        with open(p) as f:
            return json.load(f)


def main():
    """CLI for creating mock environments"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Generate Caldera Mock environment from system topology"
    )
    parser.add_argument(
        "--system-config",
        default="data/system_template.yaml",
        help="Path to system topology configuration"
    )
    parser.add_argument(
        "--caldera-path",
        help="Path to Caldera installation (to write files directly)"
    )
    parser.add_argument(
        "--export-graph",
        action="store_true",
        help="Export to attack graph env.yaml format"
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Output directory for generated files"
    )
    
    args = parser.parse_args()
    
    # Load system configuration
    print(f"Loading system configuration from {args.system_config}...")
    try:
        system_config = load_system_config(args.system_config)
    except FileNotFoundError:
        print(f"Error: System config file not found: {args.system_config}")
        print("Create a system_template.yaml file first!")
        return 1
    
    # Create mock environment
    manager = MockEnvironmentManager(caldera_path=args.caldera_path)
    
    if args.export_graph:
        # Export to attack graph format
        graph_config = manager.export_to_attack_graph_format()
        output_path = Path(args.output_dir) / "env_mock.yaml"
        with open(output_path, 'w') as f:
            yaml.dump(graph_config, f, default_flow_style=False)
        print(f"\n✓ Exported attack graph config to {output_path}")
    else:
        # Create full mock environment
        paths = manager.create_full_mock_environment(
            system_config, 
            args.caldera_path
        )
    
    return 0


if __name__ == "__main__":
    exit(main())

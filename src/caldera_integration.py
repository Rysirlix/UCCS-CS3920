#!/usr/bin/env python3
"""
caldera_integration.py - Enhanced Caldera client with Mock plugin support
Handles both real agents and simulated mock agents for safe testing
"""

from typing import Dict, List, Any, Optional
import requests
import time
import json
from datetime import datetime


class CalderaClient:
    """
    Client for interacting with MITRE Caldera C2 server
    Supports both real agents and mock plugin simulated agents
    """
    
    def __init__(self, base_url: str = "http://localhost:8888", 
                 api_key: Optional[str] = "ADMIN123",
                 mock_mode: bool = False,
                 simulation_mode: bool = False):
        """
        Initialize Caldera client
        
        Args:
            base_url: URL of Caldera server
            api_key: API key for authentication (if required)
            mock_mode: If True, will work with mock plugin agents
        """
        self.base_url = base_url.rstrip('/')
        self.headers = {"KEY": api_key} if api_key else {}
        self.headers["Content-Type"] = "application/json"
        self.mock_mode = mock_mode
        
    def test_connection(self) -> bool:
        """Test if Caldera server is reachable"""
        try:
            response = requests.get(
                f"{self.base_url}/api/v2/health",
                headers=self.headers,
                timeout=5
            )
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False
    
    def discover_agents(self, group: Optional[str] = None) -> List[Dict]:
        """
        Get all connected Caldera agents (real or mock)
        
        Args:
            group: Filter by agent group (e.g., 'simulation' for mock agents)
            
        Returns:
            List of agent dictionaries
        """
        try:
            response = requests.get(
                f"{self.base_url}/api/v2/agents",
                headers=self.headers
            )
            response.raise_for_status()
            agents = response.json()
            
            # Filter by group if specified
            if group:
                agents = [a for a in agents if a.get("group") == group]
            
            # If in mock mode, prefer simulation group
            if self.mock_mode:
                mock_agents = [a for a in agents if a.get("group") == "simulation"]
                if mock_agents:
                    return mock_agents
            
            return agents
            
        except requests.exceptions.RequestException as e:
            print(f"Error discovering agents: {e}")
            return []
    
    def get_abilities(self, tactic: Optional[str] = None) -> List[Dict]:
        """
        Fetch available attack abilities/techniques from Caldera
        
        Args:
            tactic: Filter by MITRE ATT&CK tactic (e.g., 'privilege-escalation')
            
        Returns:
            List of ability dictionaries
        """
        try:
            response = requests.get(
                f"{self.base_url}/api/v2/abilities",
                headers=self.headers
            )
            response.raise_for_status()
            abilities = response.json()
            
            if tactic:
                abilities = [a for a in abilities if a.get("tactic") == tactic]
            
            return abilities
            
        except requests.exceptions.RequestException as e:
            print(f"Error fetching abilities: {e}")
            return []
    
    def create_operation(self, name: str, adversary_id: str = None,
                        group: str = "red", auto_close: bool = False,
                        jitter: str = "2/8") -> Dict:
        """
        Create a new Caldera operation
        
        Args:
            name: Operation name
            adversary_id: ID of adversary profile to use
            group: Agent group to target
            auto_close: Whether to auto-close operation when complete
            jitter: Beacon jitter (format: "min/max" in seconds)
            
        Returns:
            Operation details including operation ID
        """
        # If mock mode and no group specified, use simulation group
        if self.mock_mode and group == "red":
            group = "simulation"
        
        payload = {
            "name": name,
            "group": group,
            "auto_close": auto_close,
            "jitter": jitter,
            "state": "running"
        }
        
        if adversary_id:
            payload["adversary"] = {"adversary_id": adversary_id}
        
        try:
            response = requests.post(
                f"{self.base_url}/api/v2/operations",
                headers=self.headers,
                json=payload
            )
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            print(f"Error creating operation: {e}")
            return {}
    
    def get_operation(self, operation_id: str) -> Dict:
        """Get details of a specific operation"""
        try:
            response = requests.get(
                f"{self.base_url}/api/v2/operations/{operation_id}",
                headers=self.headers
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching operation: {e}")
            return {}
    
    def stop_operation(self, operation_id: str) -> bool:
        """Stop a running operation"""
        try:
            payload = {"state": "finished"}
            response = requests.patch(
                f"{self.base_url}/api/v2/operations/{operation_id}",
                headers=self.headers,
                json=payload
            )
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            print(f"Error stopping operation: {e}")
            return False
    
    def map_technique_to_ability(self, technique: str) -> Optional[str]:
        """
        Map ATT&CK technique ID to Caldera ability ID
        
        Args:
            technique: ATT&CK technique string (e.g., "T1566 Phishing")
            
        Returns:
            Caldera ability ID or None
        """
        # Extract technique ID
        technique_id = technique.split()[0] if " " in technique else technique
        
        # Get all abilities
        abilities = self.get_abilities()
        
        # Find matching ability
        for ability in abilities:
            if ability.get("technique_id") == technique_id:
                return ability.get("ability_id")
        
        return None
    
    def execute_ability(self, operation_id: str, ability_id: str,
                       agent_paw: str, facts: Optional[Dict] = None) -> str:
        """
        Execute a specific ability on an agent
        
        Args:
            operation_id: Operation ID
            ability_id: Ability to execute
            agent_paw: Agent identifier
            facts: Optional facts/parameters for the ability
            
        Returns:
            Link ID for tracking execution
        """
        payload = {
            "paw": agent_paw,
            "ability_id": ability_id
        }
        
        if facts:
            payload["facts"] = facts
        
        try:
            response = requests.post(
                f"{self.base_url}/api/v2/operations/{operation_id}/potential-links",
                headers=self.headers,
                json=payload
            )
            response.raise_for_status()
            result = response.json()
            return result.get("id", "")
            
        except requests.exceptions.RequestException as e:
            print(f"Error executing ability: {e}")
            return ""
    
    def get_link_result(self, operation_id: str, link_id: str,
                       timeout: int = 60) -> Dict:
        """
        Wait for and retrieve ability execution result
        
        Args:
            operation_id: Operation ID
            link_id: Link ID from execute_ability
            timeout: Maximum time to wait in seconds
            
        Returns:
            Dictionary with execution results
        """
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                operation = self.get_operation(operation_id)
                
                # Find the link in operation
                for link in operation.get("chain", []):
                    if link.get("id") == link_id:
                        status = link.get("status")
                        
                        # Check if execution is complete
                        if status in ["success", "failure", "timeout"]:
                            return {
                                "status": status,
                                "output": link.get("output", ""),
                                "pid": link.get("pid"),
                                "detected": link.get("visibility", {}).get("score", 0) > 50
                            }
                
                # Wait before checking again
                time.sleep(2)
                
            except Exception as e:
                print(f"Error checking link result: {e}")
                break
        
        return {
            "status": "timeout",
            "output": "Execution timed out",
            "detected": False
        }
    
    def execute_attack_path(self, path: List[Dict], operation_name: str,
                           agents: List[str]) -> Dict:
        """
        Execute a complete attack path from your attack graph
        
        Args:
            path: List of edges from attack graph (each with technique, etc.)
            operation_name: Name for this operation
            agents: List of agent PAWs to use
            
        Returns:
            Dictionary with execution results
        """
        print(f"\n{'='*60}")
        print(f"Executing Attack Path: {operation_name}")
        print(f"Mock Mode: {self.mock_mode}")
        print(f"{'='*60}\n")
        
        # Create operation
        operation = self.create_operation(
            operation_name,
            group="simulation" if self.mock_mode else "red"
        )
        
        if not operation:
            return {
                "error": "Failed to create operation",
                "operation_id": None,
                "results": []
            }
        
        operation_id = operation.get("id")
        print(f"✓ Created operation: {operation_id}")
        
        results = []
        current_agent_idx = 0
        
        # Execute each step in the path
        for i, step in enumerate(path, 1):
            technique = step.get("technique", "Unknown")
            print(f"\n[Step {i}/{len(path)}] {technique}")
            
            # Map technique to ability
            ability_id = self.map_technique_to_ability(technique)
            
            if not ability_id:
                print(f"  ✗ No ability found for {technique}")
                results.append({
                    "step": technique,
                    "status": "skipped",
                    "output": "No matching ability found",
                    "detected": False
                })
                continue
            
            # Select appropriate agent
            agent_paw = agents[current_agent_idx % len(agents)]
            print(f"  → Executing on agent: {agent_paw}")
            
            # Execute ability
            link_id = self.execute_ability(
                operation_id,
                ability_id,
                agent_paw
            )
            
            if not link_id:
                print(f"  ✗ Failed to execute")
                results.append({
                    "step": technique,
                    "status": "failed",
                    "output": "Execution failed",
                    "detected": False
                })
                break
            
            # Wait for result
            print(f"  ⏳ Waiting for result...")
            result = self.get_link_result(operation_id, link_id)
            
            status_icon = "✓" if result["status"] == "success" else "✗"
            detected_icon = "🔴" if result.get("detected") else "🟢"
            print(f"  {status_icon} Status: {result['status']} {detected_icon}")
            
            results.append({
                "step": technique,
                "status": result["status"],
                "output": result.get("output", ""),
                "detected": result.get("detected", False)
            })
            
            # Stop if step failed
            if result["status"] != "success":
                print(f"\n⚠️  Path execution stopped at step {i}")
                break
        
        print(f"\n{'='*60}")
        print(f"Path Execution Complete")
        print(f"Completed: {len(results)}/{len(path)} steps")
        print(f"Successful: {sum(1 for r in results if r['status'] == 'success')}")
        print(f"Detected: {sum(1 for r in results if r.get('detected'))}")
        print(f"{'='*60}\n")
        
        return {
            "operation_id": operation_id,
            "completed_steps": len(results),
            "total_steps": len(path),
            "results": results,
            "timestamp": datetime.now().isoformat()
        }
    
    def list_operations(self, state: Optional[str] = None) -> List[Dict]:
        """
        List all operations
        
        Args:
            state: Filter by state (running, finished, etc.)
        """
        try:
            response = requests.get(
                f"{self.base_url}/api/v2/operations",
                headers=self.headers
            )
            response.raise_for_status()
            operations = response.json()
            
            if state:
                operations = [o for o in operations if o.get("state") == state]
            
            return operations
            
        except requests.exceptions.RequestException as e:
            print(f"Error listing operations: {e}")
            return []
    
    def get_mock_agents_status(self) -> Dict[str, Any]:
        """
        Get status of mock plugin agents (only in mock mode)
        
        Returns:
            Summary of mock environment
        """
        if not self.mock_mode:
            return {"error": "Not in mock mode"}
        
        agents = self.discover_agents(group="simulation")
        
        return {
            "mock_mode": True,
            "total_agents": len(agents),
            "agents_by_platform": self._group_by(agents, "platform"),
            "agents_by_privilege": self._group_by(agents, "privilege"),
            "active_agents": [a for a in agents if a.get("alive")],
            "agents": agents
        }
    
    def _group_by(self, items: List[Dict], key: str) -> Dict[str, int]:
        """Helper to group items by a key"""
        groups = {}
        for item in items:
            value = item.get(key, "unknown")
            groups[value] = groups.get(value, 0) + 1
        return groups


def create_mock_caldera_client(base_url: str = "http://localhost:8888",
                                api_key: Optional[str] = None) -> CalderaClient:
    """
    Factory function to create a Caldera client in mock mode
    
    This is the recommended way to initialize for testing with mock agents
    """
    return CalderaClient(base_url=base_url, api_key=api_key, mock_mode=True)


if __name__ == "__main__":
    """Test the Caldera integration"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Test Caldera integration")
    parser.add_argument("--url", default="http://localhost:8888")
    parser.add_argument("--api-key", help="Caldera API key")
    parser.add_argument("--mock", action="store_true", help="Use mock mode")
    parser.add_argument("--test-connection", action="store_true")
    parser.add_argument("--list-agents", action="store_true")
    parser.add_argument("--list-abilities", action="store_true")
    
    args = parser.parse_args()
    
    client = CalderaClient(args.url, args.api_key, mock_mode=args.mock)
    
    if args.test_connection:
        print(f"Testing connection to {args.url}...")
        if client.test_connection():
            print("✓ Connected successfully")
        else:
            print("✗ Connection failed")
    
    if args.list_agents:
        print("\nDiscovering agents...")
        agents = client.discover_agents()
        print(f"Found {len(agents)} agents:")
        for agent in agents:
            print(f"  - {agent.get('paw')}: {agent.get('host')} "
                  f"({agent.get('platform')}) - {agent.get('group')}")
    
    if args.list_abilities:
        print("\nFetching abilities...")
        abilities = client.get_abilities()
        print(f"Found {len(abilities)} abilities")
        for ability in abilities[:10]:  # Show first 10
            print(f"  - {ability.get('ability_id')}: {ability.get('name')} "
                  f"({ability.get('tactic')})")
    
    if args.mock:
        print("\n" + "="*60)
        print("Mock Environment Status")
        print("="*60)
        status = client.get_mock_agents_status()
        print(json.dumps(status, indent=2))

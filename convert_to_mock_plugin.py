#!/usr/bin/env python3
"""
convert_to_mock_plugin.py - Convert your generated files to MITRE Mock plugin format
This adapts your mock_agents.yml and mock_responses.yml to work with the real mock plugin
"""

import yaml
from pathlib import Path
from typing import Dict, List


def convert_agents_to_mock_format(input_file: str = "mock_agents.yml", 
                                   output_file: str = "agents.yml") -> None:
    """
    Convert your generated agents to mock plugin format
    Good news: Your format is already compatible! Just need minor tweaks.
    """
    print(f"Converting {input_file} to mock plugin format...")
    
    with open(input_file, 'r') as f:
        agents = yaml.safe_load(f)
    
    # Your format is already correct! The mock plugin uses the same structure.
    # Just ensure all required fields are present
    for agent in agents:
        # Ensure executors is a list (not dict)
        if isinstance(agent.get('executors'), dict):
            agent['executors'] = list(agent['executors'].keys())
        
        # Ensure required fields
        agent.setdefault('enabled', True)
        agent.setdefault('privilege', 'User')
        agent.setdefault('c2', 'http')
    
    # Write to output
    with open(output_file, 'w') as f:
        yaml.dump(agents, f, default_flow_style=False, sort_keys=False)
    
    print(f"✓ Converted {len(agents)} agents to {output_file}")
    print(f"\n  Next step: Copy to <caldera>/plugins/mock/conf/agents.yml")


def convert_responses_to_scenario(input_file: str = "mock_responses.yml",
                                   output_file: str = "scenario_corporate.yml",
                                   scenario_name: str = "corporate_network") -> None:
    """
    Convert your mock_responses.yml to mock plugin scenario format
    
    The mock plugin uses scenario files that map ability_id -> response
    Your format uses: {host}_{technique} -> response
    We need to convert technique IDs to ability IDs
    """
    print(f"\nConverting {input_file} to scenario format...")
    
    with open(input_file, 'r') as f:
        responses = yaml.safe_load(f)
    
    # Map your technique IDs to Caldera ability IDs
    # This is a simplified mapping - you may need to customize based on your Caldera version
    technique_to_ability = {
        'T1003': '7049e3ec-b822-4fdf-a4ac-18190f9b66d1',  # Credential Dumping (Powerkatz)
        'T1059': '1b4fb81c-8090-426c-93ab-0c4ec6ac0385',  # Command execution
        'T1068': 'a0676fe1-cd52-482e-8dde-349b73f9aa69',  # Privilege escalation
        'T1078': 'c0da588f-79f0-4263-8998-7496b1a40596',  # Valid accounts
        'T1212': '3a2ce3d5-e9e2-4344-ae23-470432ff8687',  # Exploitation for credential access
        'T1558': '7049e3ec-b822-4fdf-a4ac-18190f9b66d1',  # Kerberoasting
        'T1041': '3b5db901-2cb8-4df7-8043-c4628a6a5d5a',  # Exfiltration over C2
    }
    
    # Build scenario structure
    scenario = {
        'name': scenario_name,
        'type': 'advanced',
        'responses': []
    }
    
    # Convert responses
    ability_responses = {}
    for key, response in responses.items():
        # Parse key format: {host}_{technique}
        if '_T' in key:
            parts = key.rsplit('_', 1)
            if len(parts) == 2:
                host, technique = parts
                technique = technique.split('.')[0]  # Remove sub-technique
                
                # Map to ability ID
                ability_id = technique_to_ability.get(technique)
                if ability_id:
                    # Store response data for this ability
                    if ability_id not in ability_responses:
                        ability_responses[ability_id] = {
                            'ability_id': ability_id,
                            'hosts': {},
                            'output': response.get('output', ''),
                            'status': response.get('status', 'success')
                        }
                    
                    ability_responses[ability_id]['hosts'][host] = response
    
    # Add to scenario
    for ability_id in ability_responses:
        scenario['responses'].append({
            'ability_id': ability_id
        })
    
    # Write scenario file
    with open(output_file, 'w') as f:
        yaml.dump(scenario, f, default_flow_style=False, sort_keys=False)
    
    print(f"✓ Created scenario file: {output_file}")
    print(f"  Mapped {len(ability_responses)} abilities")
    print(f"\n  Next step: Copy to <caldera>/plugins/mock/conf/scenarios/{output_file}")
    
    # Also create a detailed responses file for reference
    detailed_file = output_file.replace('.yml', '_detailed.yml')
    with open(detailed_file, 'w') as f:
        yaml.dump(ability_responses, f, default_flow_style=False)
    
    print(f"✓ Created detailed responses: {detailed_file} (for reference)")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Convert generated files to MITRE Mock plugin format"
    )
    parser.add_argument(
        "--agents-input",
        default="mock_agents.yml",
        help="Your generated agents file"
    )
    parser.add_argument(
        "--responses-input", 
        default="mock_responses.yml",
        help="Your generated responses file"
    )
    parser.add_argument(
        "--scenario-name",
        default="corporate_network",
        help="Name for the scenario"
    )
    parser.add_argument(
        "--caldera-path",
        help="Path to Caldera installation (for instructions)"
    )
    
    args = parser.parse_args()
    
    print("="*70)
    print("MOCK PLUGIN FORMAT CONVERTER")
    print("="*70)
    
    # Check if input files exist
    agents_path = Path(args.agents_input)
    responses_path = Path(args.responses_input)
    
    if not agents_path.exists():
        print(f"\n✗ Error: {args.agents_input} not found")
        print(f"  Run mock_environment.py first to generate this file")
        return 1
    
    # Convert agents
    convert_agents_to_mock_format(
        args.agents_input,
        "agents.yml"
    )
    
    # Convert responses (if exists)
    if responses_path.exists():
        convert_responses_to_scenario(
            args.responses_input,
            f"scenario_{args.scenario_name}.yml",
            args.scenario_name
        )
    else:
        print(f"\n⚠ Warning: {args.responses_input} not found")
        print(f"  Skipping scenario conversion")
    
    # Create integration instructions
    print("\n" + "="*70)
    print("Creating integration instructions...")
    print("="*70)
    
    create_integration_instructions(args.caldera_path)
    
    print("\n" + "="*70)
    print("CONVERSION COMPLETE")
    print("="*70)
    print("\nGenerated files:")
    print("  ✓ agents.yml - Ready for plugins/mock/conf/")
    if responses_path.exists():
        print(f"  ✓ scenario_{args.scenario_name}.yml - Ready for plugins/mock/conf/scenarios/")
    print("  ✓ MOCK_PLUGIN_INTEGRATION.md - Integration guide")
    print("\nNext: Follow instructions in MOCK_PLUGIN_INTEGRATION.md")
    print("="*70)
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())

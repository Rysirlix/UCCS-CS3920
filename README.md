# UCCS-CS3920 Attack Path Ranking

This project integrates **MITRE Caldera** with a custom **attack path planning and ranking system**.  
A simulated (“mock”) environment is generated to provide fake hosts, vulnerabilities, and attack surfaces, which are then graphed and analyzed by the system.

---

## Prerequisites

Before installation, ensure you have:

- **Python 3.10 – 3.12**
- **pip**
- **git**
- **Node.js (v20+)**
- **Linux / WSL2 / macOS**

---

##  1. Clone and Set Up MITRE Caldera

```bash
git clone https://github.com/mitre/caldera.git --recursive
cd caldera
```

## 2. Create and activate a python virtual environment

```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 3. Verify that the Caldera Server runs correctly

```
python3 server.py --insecure
```
If the UI loads and Caldera is displayed in terminal then the clone worked correctly

## 4. Install Mock Plugin for Caldera

Navigate to the plugins directory
```
cd plugins
git clone https://github.com/mitre/mock.git
```

## 5. Update the Default.yml config file

```
cd caldera/conf/default.yml
```
Add mock under plugins in this general layout
```
plugins:
  - stockpile
  - compass
  - training
  - mock
```

## 6. Start the Caldera server again to check that it loads correctly
```
python3 server.py --insecure
```

## 7. Run the python program to generate the mock environment and agents
```
python mock_workflow.py --system-config data/system_template.yaml
```
After running this command a mock_agents.yml and mock_responses.yml are generated which must be placed in these locations on the caldera side
```
Agents: <caldera>/conf/agents.yml
Mock responses: <caldera>/plugins/mock/data/mock_responses.yml
```
python mock_workflow.py \
  --system-config data/system_template.yaml \
  --export
 python src/cli.py --env results/updated_graph.yaml --visualize



 python convert_to_mock_plugin.py \
  --agents-input mock_agents.yml \
  --responses-input mock_responses.yml \
  --caldera-path /path/to/caldera


  cp agents.yml /path/to/caldera/plugins/mock/conf/agents.yml
cp scenario_corporate_network.yml /path/to/caldera/plugins/mock/conf/scenarios/

 python src/graph_viz.py --graph results/updated_graph.yaml --port 5000
 

#!/usr/bin/env python3

import sys
from pathlib import Path
from flask import Flask, Response, jsonify, request, render_template_string
import yaml
from pyvis.network import Network
import json
from datetime import datetime
from typing import Dict, List, Any

# --- Ensure repo root ---
repo_dir = Path(__file__).resolve().parent
if str(repo_dir) not in sys.path:
    sys.path.insert(0, str(repo_dir))

from graph import AttackGraph
from planner import rank_paths

# Try to import Caldera integration
try:
    from caldera_integration import CalderaClient
    CALDERA_AVAILABLE = True
except ImportError:
    CALDERA_AVAILABLE = False
    CalderaClient = None

# --- Global state for execution tracking ---
execution_state = {
    "active_operations": {},
    "execution_history": [],
    "graph_updates": []
}

# --- Load env.yaml ---
def load_env_yaml(path="data/env.yaml"):
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"{path} not found. Make sure data/env.yaml exists relative to repo root.")
    return yaml.safe_load(p.read_text())


# --- Convert adjacency to edge list ---
def edges_from_attackgraph(g: AttackGraph):
    edges = []
    for src, elist in g.adj.items():
        for e in elist:
            edges.append({
                "src": src,
                "dst": e["dst"],
                "technique": e.get("technique", "?"),
                "p": float(e.get("p", 0.5)),
                "impact": float(e.get("impact", 1.0)),
                "detect": float(e.get("detect", 0.3)),
                "time": float(e.get("time", 1.0)),
                "status": e.get("status", "not_executed")  # Track execution status
            })
    return edges


# --- Phase 6: Update graph from execution results ---
def update_graph_from_execution(g: AttackGraph, execution_results: Dict) -> AttackGraph:
    """
    Update edge probabilities and detection rates based on actual execution
    """
    updates = []
    
    for result in execution_results.get("results", []):
        technique = result.get("step")
        status = result.get("status")
        detected = result.get("detected", False)
        
        # Find and update matching edges
        for edge in g.edges:
            if edge.get("technique") == technique:
                old_p = edge.get("p", 0.5)
                old_detect = edge.get("detect", 0.3)
                
                # Update probability based on success/failure
                if status == "success":
                    edge["p"] = min(1.0, old_p * 1.2)
                    edge["status"] = "succeeded"
                elif status == "failed":
                    edge["p"] = max(0.0, old_p * 0.5)
                    edge["status"] = "failed"
                else:
                    edge["status"] = "in_progress"
                
                # Update detectability if detected
                if detected:
                    edge["detect"] = min(1.0, old_detect * 1.3)
                    edge["was_detected"] = True
                
                updates.append({
                    "technique": technique,
                    "old_p": old_p,
                    "new_p": edge["p"],
                    "old_detect": old_detect,
                    "new_detect": edge["detect"],
                    "detected": detected
                })
    
    execution_state["graph_updates"].append({
        "timestamp": datetime.now().isoformat(),
        "updates": updates
    })
    
    return g


# --- Build styled HTML with execution controls ---
def build_pyvis_html(g: AttackGraph, ranked_paths, execution_history=None):
    edges = edges_from_attackgraph(g)
    top_path = ranked_paths[0]["path"] if ranked_paths else []
    top_edges = {(e["src"], e["dst"]) for e in top_path}
    
    # Track executed edges
    executed_edges = set()
    if execution_history:
        for exec_record in execution_history:
            for result in exec_record.get("results", []):
                if result.get("status") == "success":
                    # Find matching edge
                    for e in exec_record.get("path", []):
                        executed_edges.add((e["src"], e["dst"]))

    net = Network(height='800px', width='100%', directed=True, bgcolor="#1a1a1a", font_color="white")

    # --- Layout options ---
    net.set_options("""
    var options = {
      "layout": {
        "hierarchical": {
          "enabled": true,
          "direction": "LR",
          "sortMethod": "directed",
          "levelSeparation": 200,
          "nodeSpacing": 150,
          "treeSpacing": 250
        }
      },
      "edges": {
        "arrows": {"to": {"enabled": true}},
        "smooth": {"type": "cubicBezier"},
        "font": {"align": "top", "size": 12, "face": "arial"}
      },
      "nodes": {"font": {"size": 18, "face": "arial"}, "shadow": true},
      "physics": {"enabled": false}
    }
    """)

    # --- Add nodes ---
    for n in g.assets:
        if n in g.start_nodes:
            color = "#7DCEA0"  # green
            size = 30
        elif n in g.goal_nodes:
            color = "#F5B041"  # amber
            size = 40
        else:
            color = "#5DADE2"  # blue
            size = 20
        net.add_node(n, label=n, color=color, size=size)

    # --- Add edges with execution status ---
    for e in edges:
        src, dst = e["src"], e["dst"]
        label = e.get("technique", "?")
        status = e.get("status", "not_executed")
        
        title_text = (
            f"Technique: {label}<br>"
            f"p={e['p']:.2f}, impact={e['impact']}, detect={e['detect']:.2f}, time={e['time']}<br>"
            f"Status: {status}"
        )
        
        # Color based on execution status
        if (src, dst) in executed_edges:
            if e.get("was_detected"):
                color = "#FF6B6B"  # red - detected
                width = 5
            else:
                color = "#51CF66"  # green - succeeded undetected
                width = 4
        elif (src, dst) in top_edges:
            color = "#FFD93D"  # yellow - recommended
            width = 3
        else:
            color = "gray"
            width = 1

        net.add_edge(src, dst, label=label, title=title_text,
                     color=color, width=width, font={"align": "top", "size": 10})

    html = net.generate_html()

    
    custom_css = """
    <style>
      body {
        font-family: 'Segoe UI', Roboto, sans-serif;
        background-color: #121212;
        color: #f0f0f0;
        margin: 0;
        padding: 0;
      }
      h2 {
        text-align: center;
        margin-top: 20px;
        color: #f1c40f;
        font-weight: 600;
      }
      .container {
        max-width: 1400px;
        margin: 0 auto;
        padding: 20px;
      }
      .graph-box {
        background: #1e1e1e;
        border-radius: 12px;
        box-shadow: 0 0 20px rgba(0,0,0,0.5);
        padding: 10px;
      }
      .control-panel {
        background: #1f1f1f;
        border-radius: 10px;
        padding: 20px;
        margin: 20px 0;
        box-shadow: 0 0 10px rgba(0,0,0,0.3);
      }
      .status-badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 12px;
        font-size: 0.85em;
        font-weight: bold;
        margin-left: 10px;
      }
      .status-not-executed { background: #555; color: #ddd; }
      .status-in-progress { background: #FFD93D; color: #000; }
      .status-succeeded { background: #51CF66; color: #000; }
      .status-failed { background: #FF6B6B; color: #fff; }
      .status-detected { background: #FF6B6B; color: #fff; }
      .execute-btn {
        background: #f1c40f;
        color: #000;
        border: none;
        padding: 8px 16px;
        border-radius: 6px;
        cursor: pointer;
        font-weight: bold;
        margin-right: 10px;
        transition: background 0.3s;
      }
      .execute-btn:hover {
        background: #f39c12;
      }
      .execute-btn:disabled {
        background: #555;
        cursor: not-allowed;
      }
      .stop-btn {
        background: #e74c3c;
        color: #fff;
      }
      .stop-btn:hover {
        background: #c0392b;
      }
      table {
        border-collapse: collapse;
        width: 100%;
        margin-top: 20px;
        background: #1f1f1f;
        border-radius: 10px;
        overflow: hidden;
        box-shadow: 0 0 10px rgba(0,0,0,0.3);
      }
      th, td {
        padding: 10px 12px;
        text-align: center;
      }
      th {
        background-color: #333;
        color: #f1c40f;
        text-transform: uppercase;
        font-size: 0.9em;
      }
      tr:nth-child(even) {
        background-color: #2a2a2a;
      }
      tr:hover {
        background-color: #383838;
      }
      .legend {
        background: #1f1f1f;
        border-radius: 10px;
        padding: 15px;
        margin: 20px 0;
      }
      .legend-item {
        display: inline-block;
        margin-right: 20px;
        margin-bottom: 10px;
      }
      .legend-color {
        display: inline-block;
        width: 30px;
        height: 4px;
        margin-right: 8px;
        vertical-align: middle;
      }
      .execution-log {
        background: #1a1a1a;
        border-radius: 8px;
        padding: 15px;
        margin: 20px 0;
        max-height: 400px;
        overflow-y: auto;
        font-family: 'Courier New', monospace;
        font-size: 0.9em;
      }
      .log-entry {
        padding: 5px 0;
        border-bottom: 1px solid #333;
      }
      .log-timestamp {
        color: #888;
        margin-right: 10px;
      }
      .log-success { color: #51CF66; }
      .log-failure { color: #FF6B6B; }
      .log-info { color: #5DADE2; }
      .footer {
        text-align: center;
        color: #999;
        margin-top: 40px;
        font-size: 0.85em;
      }
      .caldera-status {
        display: inline-block;
        padding: 6px 12px;
        border-radius: 6px;
        margin-left: 15px;
        font-size: 0.9em;
      }
      .caldera-connected {
        background: #51CF66;
        color: #000;
      }
      .caldera-disconnected {
        background: #FF6B6B;
        color: #fff;
      }
    </style>
    """

    # --- JavaScript for AJAX execution ---
    custom_js = """
    <script>
      async function executePath(pathIndex) {
        const btn = document.getElementById('exec-btn-' + pathIndex);
        btn.disabled = true;
        btn.textContent = 'Executing...';
        
        try {
          const response = await fetch('/execute/' + pathIndex, {
            method: 'POST'
          });
          const result = await response.json();
          
          if (result.error) {
            alert('Error: ' + result.error);
            btn.disabled = false;
            btn.textContent = 'Execute Path';
            return;
          }
          
          // Update UI
          updateExecutionLog(result);
          
          // Reload page to show updated graph
          setTimeout(() => location.reload(), 2000);
          
        } catch (error) {
          alert('Execution failed: ' + error.message);
          btn.disabled = false;
          btn.textContent = 'Execute Path';
        }
      }
      
      async function stopOperation(opId) {
        if (!confirm('Stop this operation?')) return;
        
        const response = await fetch('/stop/' + opId, {
          method: 'POST'
        });
        const result = await response.json();
        alert(result.message || 'Operation stopped');
        location.reload();
      }
      
      function updateExecutionLog(result) {
        const log = document.getElementById('execution-log');
        const timestamp = new Date().toLocaleTimeString();
        
        let entry = `<div class="log-entry">`;
        entry += `<span class="log-timestamp">[${timestamp}]</span>`;
        entry += `<span class="log-info">Started operation: ${result.operation_id}</span>`;
        entry += `</div>`;
        
        result.results.forEach(step => {
          const statusClass = step.status === 'success' ? 'log-success' : 'log-failure';
          entry += `<div class="log-entry">`;
          entry += `<span class="log-timestamp">[${timestamp}]</span>`;
          entry += `<span class="${statusClass}">${step.step}: ${step.status}</span>`;
          if (step.detected) {
            entry += ` <span class="log-failure">[DETECTED]</span>`;
          }
          entry += `</div>`;
        });
        
        log.innerHTML = entry + log.innerHTML;
      }
      
      // Auto-refresh for active operations
      setInterval(() => {
        const hasActiveOps = document.querySelectorAll('.status-in-progress').length > 0;
        if (hasActiveOps) {
          location.reload();
        }
      }, 10000); // Check every 10 seconds
    </script>
    """

    # --- Control Panel ---
    caldera_status = "connected" if CALDERA_AVAILABLE else "disconnected"
    caldera_class = "caldera-connected" if CALDERA_AVAILABLE else "caldera-disconnected"
    
    control_panel = f"""
    <div class="control-panel">
      <h3 style="margin-top:0;">Caldera Control Panel 
        <span class="caldera-status {caldera_class}">
          {'🟢 Connected' if CALDERA_AVAILABLE else '🔴 Not Available'}
        </span>
      </h3>
      <p>Execute attack paths directly via Caldera. Results will update the graph in real-time.</p>
      {f'<p style="color:#FF6B6B;">⚠️ Caldera integration not available. Install caldera_integration.py to enable execution.</p>' if not CALDERA_AVAILABLE else ''}
    </div>
    """

    # --- Legend ---
    legend_html = """
    <div class="legend">
      <h4 style="margin-top:0;">Edge Color Legend</h4>
      <div class="legend-item">
        <span class="legend-color" style="background:#51CF66;"></span>
        <span>Executed Successfully (Undetected)</span>
      </div>
      <div class="legend-item">
        <span class="legend-color" style="background:#FF6B6B;"></span>
        <span>Executed & Detected</span>
      </div>
      <div class="legend-item">
        <span class="legend-color" style="background:#FFD93D;"></span>
        <span>Recommended Path (#1 Ranked)</span>
      </div>
      <div class="legend-item">
        <span class="legend-color" style="background:gray;"></span>
        <span>Not Executed</span>
      </div>
    </div>
    """

    # --- Execution Log ---
    execution_log_html = """
    <div class="container">
      <h3 style='text-align:center;margin-top:30px;color:#f1c40f;'>Execution Log</h3>
      <div id="execution-log" class="execution-log">
    """
    
    if execution_history:
        for exec_record in reversed(execution_history[-10:]):  # Last 10
            timestamp = exec_record.get("timestamp", "Unknown")
            op_id = exec_record.get("operation_id", "Unknown")
            execution_log_html += f'<div class="log-entry"><span class="log-timestamp">[{timestamp}]</span><span class="log-info">Operation: {op_id}</span></div>'
            
            for result in exec_record.get("results", []):
                status_class = "log-success" if result["status"] == "success" else "log-failure"
                detected_tag = ' <span class="log-failure">[DETECTED]</span>' if result.get("detected") else ""
                execution_log_html += f'<div class="log-entry"><span class="log-timestamp"></span><span class="{status_class}">{result["step"]}: {result["status"]}</span>{detected_tag}</div>'
    else:
        execution_log_html += '<div class="log-entry"><span class="log-info">No execution history yet</span></div>'
    
    execution_log_html += "</div></div>"

    # --- Ranked paths table with execution controls ---
    path_list_html = """
    <div class="container">
      <h3 style='text-align:center;margin-top:30px;color:#f1c40f;'>Ranked Attack Paths</h3>
      <div style='overflow-x:auto;'>
        <table>
          <tr>
            <th>Rank</th><th>Utility</th><th>Probability</th><th>Impact</th>
            <th>Detect</th><th>Time</th><th>Techniques</th><th>Actions</th>
          </tr>
    """

    for i, r in enumerate(ranked_paths, 1):
        steps = " → ".join(e.get("technique", "?") for e in r["path"])
        
        # Check if path has been executed
        path_executed = False
        path_status = "not_executed"
        for exec_record in execution_state.get("execution_history", []):
            if exec_record.get("path_index") == i - 1:
                path_executed = True
                path_status = "succeeded" if exec_record.get("completed_steps") == len(r["path"]) else "failed"
        
        status_badge = f'<span class="status-badge status-{path_status}">{path_status.replace("_", " ").upper()}</span>'
        
        execute_btn = ""
        if CALDERA_AVAILABLE:
            if not path_executed:
                execute_btn = f'<button id="exec-btn-{i-1}" class="execute-btn" onclick="executePath({i-1})">Execute Path</button>'
            else:
                execute_btn = f'<button class="execute-btn" disabled>Executed</button>'
        
        path_list_html += (
            f"<tr>"
            f"<td>{i}</td>"
            f"<td>{r['utility']:.3f}</td>"
            f"<td>{r['prob']:.3f}</td>"
            f"<td>{r['impact']:.2f}</td>"
            f"<td>{r['detect']:.2f}</td>"
            f"<td>{r['time']:.2f}</td>"
            f"<td>{steps}</td>"
            f"<td>{execute_btn}{status_badge}</td>"
            f"</tr>"
        )
    path_list_html += "</table></div></div>"

    # --- Graph Updates Section ---
    graph_updates_html = ""
    if execution_state.get("graph_updates"):
        graph_updates_html = """
        <div class="container">
          <h3 style='text-align:center;margin-top:30px;color:#f1c40f;'>Graph Learning Updates</h3>
          <div style='overflow-x:auto;'>
            <table>
              <tr>
                <th>Technique</th><th>Old Probability</th><th>New Probability</th>
                <th>Old Detectability</th><th>New Detectability</th><th>Was Detected</th>
              </tr>
        """
        
        for update_batch in reversed(execution_state["graph_updates"][-5:]):
            for update in update_batch.get("updates", []):
                detected_icon = "🔴" if update.get("detected") else "🟢"
                graph_updates_html += (
                    f"<tr>"
                    f"<td>{update['technique']}</td>"
                    f"<td>{update['old_p']:.3f}</td>"
                    f"<td>{update['new_p']:.3f}</td>"
                    f"<td>{update['old_detect']:.3f}</td>"
                    f"<td>{update['new_detect']:.3f}</td>"
                    f"<td>{detected_icon}</td>"
                    f"</tr>"
                )
        
        graph_updates_html += "</table></div></div>"

    footer_html = "<div class='footer'>Attack Graph Visualizer with Caldera Integration © 2025</div>"

    # --- Inject everything into HTML ---
    html = html.replace("</head>", custom_css + custom_js + "\n</head>")
    html = html.replace("<body>", 
        f"<body><div class='container'><h2>Attack Graph Visualization</h2>{control_panel}{legend_html}<div class='graph-box'>")
    html = html.replace("</body>", 
        f"</div>{execution_log_html}{path_list_html}{graph_updates_html}{footer_html}</body>")

    return html


# --- Flask app ---
app = Flask(__name__)

@app.route('/')
def index():
    cfg = load_env_yaml("data/env.yaml")
    g = AttackGraph(cfg["assets"], cfg["start_nodes"], cfg["goal_nodes"], cfg["edges"])
    paths = g.enumerate_paths(max_depth=5)
    ranked = rank_paths(paths, top_k=5)
    html = build_pyvis_html(g, ranked, execution_state.get("execution_history"))
    return Response(html, mimetype='text/html')


@app.route('/execute/<int:path_index>', methods=['POST'])
def execute_path(path_index):
    """Phase 5: Execute a specific attack path via Caldera"""
    if not CALDERA_AVAILABLE:
        return jsonify({"error": "Caldera integration not available"}), 503
    
    cfg = load_env_yaml("data/env.yaml")
    g = AttackGraph(cfg["assets"], cfg["start_nodes"], cfg["goal_nodes"], cfg["edges"])
    paths = g.enumerate_paths(max_depth=5)
    ranked = rank_paths(paths, top_k=5)
    
    if path_index >= len(ranked):
        return jsonify({"error": "Invalid path index"}), 400
    
    try:
        # Initialize Caldera client
        caldera = CalderaClient(
            base_url=app.config.get("CALDERA_URL", "http://localhost:8888"),
            api_key=app.config.get("CALDERA_KEY")
        )
        
        # Get available agents
        agents = caldera.discover_agents()
        if not agents:
            return jsonify({"error": "No Caldera agents available"}), 503
        
        # Execute the path
        result = caldera.execute_attack_path(
            ranked[path_index]["path"],
            f"AutoPath_{path_index}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            [a["paw"] for a in agents]
        )
        
        # Record execution
        execution_record = {
            "timestamp": datetime.now().isoformat(),
            "path_index": path_index,
            "operation_id": result["operation_id"],
            "completed_steps": result["completed_steps"],
            "results": result["results"],
            "path": ranked[path_index]["path"]
        }
        execution_state["execution_history"].append(execution_record)
        execution_state["active_operations"][result["operation_id"]] = execution_record
        
        # Phase 6: Update graph based on execution results
        updated_graph = update_graph_from_execution(g, result)
        
        # Save updated graph back to env.yaml
        cfg["edges"] = updated_graph.edges
        with open("data/env.yaml", "w") as f:
            yaml.dump(cfg, f)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/stop/<operation_id>', methods=['POST'])
def stop_operation(operation_id):
    """Stop an active Caldera operation"""
    if not CALDERA_AVAILABLE:
        return jsonify({"error": "Caldera integration not available"}), 503
    
    try:
        caldera = CalderaClient(
            base_url=app.config.get("CALDERA_URL", "http://localhost:8888"),
            api_key=app.config.get("CALDERA_KEY")
        )
        
        caldera.stop_operation(operation_id)
        
        if operation_id in execution_state["active_operations"]:
            del execution_state["active_operations"][operation_id]
        
        return jsonify({"message": f"Operation {operation_id} stopped"})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/status')
def status():
    """Get current execution status"""
    return jsonify({
        "caldera_available": CALDERA_AVAILABLE,
        "active_operations": len(execution_state["active_operations"]),
        "total_executions": len(execution_state["execution_history"]),
        "graph_updates": len(execution_state["graph_updates"])
    })


@app.route('/history')
def history():
    """Get execution history as JSON"""
    return jsonify(execution_state["execution_history"])


# --- Optional standalone mode ---
def visualize_attack_graph(env_file="data/env.yaml"):
    cfg = load_env_yaml(env_file)
    g = AttackGraph(cfg["assets"], cfg["start_nodes"], cfg["goal_nodes"], cfg["edges"])
    paths = g.enumerate_paths(max_depth=5)
    ranked = rank_paths(paths, top_k=5)
    html_file = Path("attack_graph.html")
    with html_file.open("w") as f:
        f.write(build_pyvis_html(g, ranked, execution_state.get("execution_history")))
    print(f"Attack graph saved to {html_file.resolve()} (open in a browser)")


# --- Main entry ---
if __name__ == "__main__":
    print("=" * 60)
    print("Attack Graph Visualization with Caldera Integration")
    print("=" * 60)
    print(f"Caldera Integration: {'✓ Available' if CALDERA_AVAILABLE else '✗ Not Available'}")
    print("Starting server at http://localhost:5000")
    print("=" * 60)
    
    # Load config if available
    config_file = Path("config.yaml")
    if config_file.exists():
        with open(config_file) as f:
            config = yaml.safe_load(f)
            app.config.update(config)
    
    app.run(host='0.0.0.0', port=5000, debug=True)

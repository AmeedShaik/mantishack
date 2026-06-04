"""
mantishack_server.py
Flask bridge for Mantishack devcontainer — streams real command output via SSE.
Run inside your GitHub Codespace:
    pip install flask flask-cors
    python3 mantishack_server.py
Then forward port 6001 in Codespaces and open the dashboard on your Android browser.
"""

import os
import json
import subprocess
import threading
import queue
import uuid
import glob
import re
from flask import Flask, Response, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder=".")
CORS(app)

# Active job streams: job_id -> Queue
_streams = {}
_stream_lock = threading.Lock()

MANTISHACK_DIR = os.path.dirname(os.path.abspath(__file__))
SARIF_GLOB = os.path.join(MANTISHACK_DIR, "**", "*.sarif")

# ── Command map ────────────────────────────────────────────────────────────────

def build_command(cmd: str, repo: str, extra_args: str = "") -> list[str]:
    """Return the shell command list for a given /mantis-* command."""
    base = ["python3", os.path.join(MANTISHACK_DIR, "mantishack.py")]
    extras = extra_args.split() if extra_args else []

    mapping = {
        "scan":          base + ["scan",         "--repo", repo] + extras,
        "auth-audit":    base + ["scan",         "--repo", repo, "--policy-groups", "auth,logging"] + extras,
        "sca":           base + ["sca",          "--repo", repo] + extras,
        "codeql":        base + ["codeql",       "--repo", repo] + extras,
        "fuzz":          base + ["fuzz",         "--repo", repo] + extras,
        "crash-analysis":base + ["crash",        "--repo", repo] + extras,
        "oss-forensics": base + ["oss-forensics","--repo", repo] + extras,
        "understand":    _claude_cmd(f"/mantis-understand --map --target {repo}"),
        "validate":      _claude_cmd(f"/mantis-validate --target {repo}"),
        "exploit":       _claude_cmd(f"/mantis-exploit --target {repo}"),
        "patch":         _claude_cmd(f"/mantis-patch --target {repo}"),
        "agentic":       _claude_cmd(f"/mantis-agentic --target {repo}"),
    }
    return mapping.get(cmd, base + ["scan", "--repo", repo])

def _claude_cmd(slash_cmd: str) -> list[str]:
    return ["claude", "--print", slash_cmd]

# ── SSE streaming ──────────────────────────────────────────────────────────────

def _run_job(job_id: str, cmd: list[str], cwd: str):
    q = _streams[job_id]
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=cwd,
        )
        for line in proc.stdout:
            q.put({"type": "log", "text": line.rstrip()})
        proc.wait()
        # Try to parse SARIF findings after run
        findings = _parse_latest_sarif()
        q.put({"type": "findings", "data": findings})
        q.put({"type": "done", "code": proc.returncode})
    except FileNotFoundError as e:
        q.put({"type": "log", "text": f"[ERROR] Command not found: {e}", "level": "error"})
        q.put({"type": "done", "code": 1})
    except Exception as e:
        q.put({"type": "log", "text": f"[ERROR] {e}", "level": "error"})
        q.put({"type": "done", "code": 1})
    finally:
        q.put(None)  # sentinel

def _parse_latest_sarif() -> list[dict]:
    """Find the most recent SARIF file and extract findings."""
    files = sorted(glob.glob(SARIF_GLOB, recursive=True), key=os.path.getmtime, reverse=True)
    if not files:
        return []
    try:
        with open(files[0]) as f:
            sarif = json.load(f)
        findings = []
        for run in sarif.get("runs", []):
            rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "unknown")
                sev = _sarif_severity(result, rules.get(rule_id, {}))
                loc = result.get("locations", [{}])[0]
                phys = loc.get("physicalLocation", {})
                file_path = phys.get("artifactLocation", {}).get("uri", "?")
                line = phys.get("region", {}).get("startLine", 0)
                msg = result.get("message", {}).get("text", "")
                findings.append({
                    "severity": sev,
                    "rule": rule_id,
                    "file": os.path.basename(file_path),
                    "line": line,
                    "message": msg[:120],
                    "status": "Pending",
                })
        return findings
    except Exception:
        return []

def _sarif_severity(result: dict, rule: dict) -> str:
    level = result.get("level", "")
    props = rule.get("properties", {})
    sev = props.get("security-severity", "")
    if level == "error" or (sev and float(sev) >= 9.0):
        return "critical"
    if level == "warning" or (sev and float(sev) >= 7.0):
        return "high"
    if sev and float(sev) >= 4.0:
        return "medium"
    return "low"

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "cwd": MANTISHACK_DIR})

@app.route("/api/run", methods=["POST"])
def run_command():
    body = request.get_json(force=True) or {}
    cmd_name = body.get("command", "scan")
    repo = body.get("repo", "").strip() or MANTISHACK_DIR
    extra = body.get("extra", "")

    if not os.path.exists(repo):
        return jsonify({"error": f"Repo path not found: {repo}"}), 400

    cmd = build_command(cmd_name, repo, extra)
    job_id = str(uuid.uuid4())[:8]
    q = queue.Queue()
    with _stream_lock:
        _streams[job_id] = q

    t = threading.Thread(target=_run_job, args=(job_id, cmd, MANTISHACK_DIR), daemon=True)
    t.start()

    return jsonify({"job_id": job_id, "command": cmd})

@app.route("/api/stream/<job_id>")
def stream(job_id: str):
    with _stream_lock:
        q = _streams.get(job_id)
    if q is None:
        return jsonify({"error": "job not found"}), 404

    def generate():
        while True:
            msg = q.get()
            if msg is None:
                yield "data: " + json.dumps({"type": "end"}) + "\n\n"
                break
            yield "data: " + json.dumps(msg) + "\n\n"
        with _stream_lock:
            _streams.pop(job_id, None)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.route("/api/findings")
def get_findings():
    return jsonify(_parse_latest_sarif())

@app.route("/")
def index():
    return send_from_directory(".", "mantishack_dashboard.html")

# ── Main ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("  Mantishack Bridge Server")
    print("  http://localhost:6001")
    print("  Forward port 6001 in Codespaces → open on Android")
    print("=" * 55)
    app.run(host="0.0.0.0", port=6001, debug=False, threaded=True)

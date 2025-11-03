import os, sys, subprocess, platform, shlex
ENV = ".venv"
REQS_FILE = "requirements.txt"
ENTRY = "src/cli.py"

def run(cmd):
    print(">", cmd if isinstance(cmd, str) else " ".join(cmd))
    subprocess.check_call(cmd if isinstance(cmd, list) else shlex.split(cmd))

def py(venv): return os.path.join(venv, "Scripts" if platform.system()=="Windows" else "bin", "python")
def pip(venv): return [py(venv), "-m", "pip"]

if not os.path.isdir(ENV):
    run([sys.executable, "-m", "venv", ENV])
    run(pip(ENV) + ["install", "--upgrade", "pip", "setuptools", "wheel"])
if os.path.exists(REQS_FILE):
    run(pip(ENV) + ["install", "-r", REQS_FILE])
run([py(ENV), ENTRY, *sys.argv[1:]])


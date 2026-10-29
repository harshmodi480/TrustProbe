import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
VENV_PYTHON = os.path.join(ROOT, ".venv", "Scripts", "python.exe")

def is_setup_done():
    if not os.path.isfile(VENV_PYTHON):
        return False
    result = subprocess.run([VENV_PYTHON, "-c", "import trustprobe"], capture_output=True)
    return result.returncode == 0

if not is_setup_done():
    print("First-time setup...")
    venv_path = os.path.join(ROOT, ".venv")
    subprocess.run([sys.executable, "-m", "venv", venv_path], check=True)
    subprocess.run([VENV_PYTHON, "-m", "pip", "install", "--upgrade", "pip"], check=True)
    subprocess.run([VENV_PYTHON, "-m", "pip", "install", "--no-cache-dir", "--force-reinstall", "pydantic", "pydantic-core"], check=True)
    subprocess.run([VENV_PYTHON, "-m", "pip", "install", "--no-cache-dir", "-e", ROOT], check=True)
    subprocess.run([VENV_PYTHON, "-m", "pip", "install", "--no-cache-dir",
                    "fastapi>=0.110", "uvicorn[standard]>=0.29", "sse-starlette>=1.8"], check=True)
    print("Setup complete.")

result = subprocess.run([VENV_PYTHON, "-m", "trustprobe"] + sys.argv[1:])
sys.exit(result.returncode)

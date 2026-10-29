import os
import subprocess
import sys

if sys.version_info < (3, 11):
    print(f"Python 3.11+ is required. You are running {sys.version}.")
    print("Download the latest Python from https://python.org")
    sys.exit(1)

ROOT = os.path.dirname(os.path.abspath(__file__))
VENV_PYTHON = os.path.join(ROOT, ".venv", "Scripts", "python.exe")

def is_setup_done():
    if not os.path.isfile(VENV_PYTHON):
        return False
    result = subprocess.run([VENV_PYTHON, "-c", "import trustprobe"], capture_output=True)
    return result.returncode == 0

if not is_setup_done():
    print("First-time setup — this may take a minute...")
    try:
        venv_path = os.path.join(ROOT, ".venv")
        subprocess.run([sys.executable, "-m", "venv", venv_path], check=True)
        subprocess.run([VENV_PYTHON, "-m", "pip", "install", "--upgrade", "pip"], check=True)
        subprocess.run([VENV_PYTHON, "-m", "pip", "install", "--no-cache-dir", "--force-reinstall", "pydantic", "pydantic-core"], check=True)
        subprocess.run([VENV_PYTHON, "-m", "pip", "install", "--no-cache-dir", "-e", ROOT], check=True)
        subprocess.run([VENV_PYTHON, "-m", "pip", "install", "--no-cache-dir",
                        "fastapi>=0.110", "uvicorn[standard]>=0.29", "sse-starlette>=1.8"], check=True)

        # Install requirements for every demo server so local-path scans work
        # without Docker (the venv Python is used as the interpreter).
        demo_root = os.path.join(ROOT, "demo_servers")
        if os.path.isdir(demo_root):
            for entry in os.listdir(demo_root):
                req = os.path.join(demo_root, entry, "requirements.txt")
                if os.path.isfile(req):
                    subprocess.run([VENV_PYTHON, "-m", "pip", "install", "--no-cache-dir", "-r", req], check=True)

        print("Setup complete.")
    except subprocess.CalledProcessError as e:
        print(f"\nSetup failed: {e}")
        print("Possible causes: no internet connection, insufficient disk space, or a pip error.")
        print("Try deleting the .venv folder and running again.")
        sys.exit(1)

# No arguments → start the web app
if len(sys.argv) == 1:
    port = "7860"
    print(f"Starting TrustProbe web app at http://localhost:{port}")
    result = subprocess.run([VENV_PYTHON, "-m", "uvicorn", "web_app:app", "--port", port])
    sys.exit(result.returncode)

# "--port <n>" as the only argument → start web app on that port
if len(sys.argv) == 3 and sys.argv[1] == "--port":
    port = sys.argv[2]
    print(f"Starting TrustProbe web app at http://localhost:{port}")
    result = subprocess.run([VENV_PYTHON, "-m", "uvicorn", "web_app:app", "--port", port])
    sys.exit(result.returncode)

# Any other arguments → pass through to the trustprobe CLI
result = subprocess.run([VENV_PYTHON, "-m", "trustprobe"] + sys.argv[1:])
sys.exit(result.returncode)

"""Start every SIDRMS service that exists in the services folder.

Usage: python main.py   (stop everything with Ctrl+C)
"""

import subprocess
import sys
import time
from pathlib import Path

from common.config import PORTS

BASE_DIR = Path(__file__).resolve().parent


def main():
    """Launch each available service in its own process and stop them all on Ctrl+C."""
    processes = []
    for name, port in PORTS.items():
        if not (BASE_DIR / "services" / name / "app.py").exists():
            print(f"  {name:<16} skipped (not implemented yet)")
            continue
        process = subprocess.Popen([sys.executable, "-m", f"services.{name}.app"], cwd=BASE_DIR)
        processes.append((name, process))
        print(f"  {name:<16} running on http://127.0.0.1:{port}")

    if not processes:
        sys.exit("No services found.")
    print("All available services started. Press Ctrl+C to stop.")

    try:
        while True:
            for name, process in list(processes):
                if process.poll() is not None:
                    print(f"  {name} stopped unexpectedly (exit code {process.returncode})")
                    processes.remove((name, process))
            if not processes:
                break
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping services...")
    finally:
        for _, process in processes:
            process.terminate()
        for _, process in processes:
            process.wait()


if __name__ == "__main__":
    main()

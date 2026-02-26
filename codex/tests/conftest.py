import sys
from pathlib import Path


# Ensure `scanners/`, `reports/`, etc. are importable when running pytest from outside
# this directory (e.g. `pytest php-analyzer/tests` from the repo root).
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


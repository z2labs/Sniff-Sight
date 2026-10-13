"""Default locations. Everything can be overridden:

* SNIFF_WORKDIR      - working directory for data and helper venvs (default: the folder that contains the repo)
* SNIFF_CAPTURES     - capture output (default: <workdir>/captures)
* SNIFF_SPINEL_VENV  - Python venv with pyspinel for the RCP sniffer (default: <workdir>/spinel_venv)
"""
import os

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK_DIR = os.environ.get("SNIFF_WORKDIR") or os.path.dirname(REPO_DIR)
DEFAULT_CAPTURES = os.environ.get("SNIFF_CAPTURES") or os.path.join(WORK_DIR, "captures")
DEFAULT_SPINEL_VENV = os.environ.get("SNIFF_SPINEL_VENV") or os.path.join(WORK_DIR, "spinel_venv")

"""Makes the proxy suite runnable from the repo root as well as from proxy/.

detect.py calls load_rules('rules.toml') at import time, resolved against the
CWD, so the proxy package only imports cleanly when the working directory is
proxy/. Rather than require everyone to remember that, pin it here.
"""

import os
import pathlib
import sys

PROXY_DIR = pathlib.Path(__file__).resolve().parents[1]

sys.path.insert(0, str(PROXY_DIR))
os.chdir(PROXY_DIR)

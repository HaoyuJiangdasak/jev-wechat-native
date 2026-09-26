"""Put the adapter sources on sys.path so the tests can import them.

The tests live in a subdirectory while the modules they exercise sit one level
up, so each test file imports this first.
"""
import sys
from pathlib import Path

APP = Path(__file__).resolve().parent.parent
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

"""Entry point: `python src/main.py <cmd> ...`

Keeps the package importable without installing anything.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rekit.cli import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())

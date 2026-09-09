#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.14"
# dependencies = ["mnemocode @ git+https://github.com/korthane/mnemocode"]
# ///
"""Bootstrap so the tool runs straight from its raw URL.

    uv run https://raw.githubusercontent.com/korthane/mnemocode/main/main.py \\
        encode --input file:key.txt

uv installs the package named above, so `english.txt` and every module come
along. Local development uses `uv run mnemocode` instead; this shim always
installs from GitHub.
"""

import sys

from mnemocode.cli import main

sys.exit(main())

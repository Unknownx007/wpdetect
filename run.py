#!/usr/bin/env python3
# WP-DETECT — Copyright (C) 2025 DEDSEC <https://github.com/Unknownx007>
# SPDX-License-Identifier: AGPL-3.0-or-later
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from wpdetect.cli import main

if __name__ == "__main__":
    sys.exit(main())

"""`python -m guard <command>` runs guard-admin; `python -m guard serve` starts the dashboard."""

import sys

from .cli import main

sys.exit(main())

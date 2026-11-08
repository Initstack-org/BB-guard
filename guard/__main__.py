"""`python -m guard` runs the admin CLI until the web service entry point exists (Stage 2, web layer)."""

import sys

from .cli import main

sys.exit(main())

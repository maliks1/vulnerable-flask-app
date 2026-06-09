# NOTE: Jika IS_DEBUG diubah, server perlu di-restart untuk perubahan berlaku efektif
from __future__ import annotations

import os

IS_DEBUG = os.environ.get("IS_DEBUG", "1")

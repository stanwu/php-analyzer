from __future__ import annotations

import tempfile
import unittest
from pathlib import Path


class TempDirTestCase(unittest.TestCase):
    def tmp_path(self) -> Path:
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        return Path(td.name)

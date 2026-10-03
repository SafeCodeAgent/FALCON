"""Tests for mapping model labels to Agent-tool model ids.

A fake catalog is written under a temporary CLAUDE_CONFIG_DIR so the test does
not depend on the machine's real cache.
"""

import importlib
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _write_catalog(config_dir, models):
    cache = os.path.join(config_dir, "cache", "model-catalog")
    os.makedirs(cache, exist_ok=True)
    with open(os.path.join(cache, "cat.json"), "w", encoding="utf-8") as handle:
        json.dump({"catalog": {"config": {"models": models}}}, handle)


SAMPLE = [
    {"id": "claude-opus-5-5", "name": "Opus 5.5", "quick_select": True, "section": "main"},
    {"id": "claude-sonnet-5-5", "name": "Sonnet 5.5", "quick_select": True, "section": "main"},
    {"id": "claude-fable-5-1", "name": "Fable 5.1", "quick_select": True, "section": "main"},
    {"id": "claude-haiku-4-5-20251001", "name": "Haiku 4.5", "quick_select": True, "section": "main"},
    {"id": "claude-opus-4-8", "name": "Opus 4.8", "quick_select": False, "section": "overflow"},
]


class WithCatalogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        _write_catalog(self.tmp, SAMPLE)
        os.environ["CLAUDE_CONFIG_DIR"] = self.tmp
        import engine.models as models_mod
        self.models = importlib.reload(models_mod)

    def tearDown(self):
        os.environ.pop("CLAUDE_CONFIG_DIR", None)

    def test_list_excludes_fable(self):
        names = [m["name"] for m in self.models.list_models()]
        self.assertIn("Opus 5.5", names)
        self.assertNotIn("Fable 5.1", names)

    def test_versioned_label_resolves_to_id(self):
        self.assertEqual(self.models.resolve("Opus 5.5"), "claude-opus-5-5")
        self.assertEqual(self.models.resolve("Opus 4.8"), "claude-opus-4-8")
        self.assertEqual(self.models.resolve("Haiku 4.5"), "claude-haiku-4-5-20251001")

    def test_family_and_main_and_fable(self):
        self.assertEqual(self.models.resolve("opus"), "claude-opus-5-5")
        self.assertEqual(self.models.resolve("main coding agent"), "main")
        self.assertIsNone(self.models.resolve("Fable 5.1"))
        self.assertIsNone(self.models.resolve("nonsense"))


class WithoutCatalogTests(unittest.TestCase):
    def setUp(self):
        os.environ["CLAUDE_CONFIG_DIR"] = tempfile.mkdtemp()  # no catalog file
        import engine.models as models_mod
        self.models = importlib.reload(models_mod)

    def tearDown(self):
        os.environ.pop("CLAUDE_CONFIG_DIR", None)

    def test_falls_back_to_family(self):
        self.assertEqual(self.models.list_models(), [])
        self.assertEqual(self.models.resolve("opus"), "opus")
        # A versioned label with no catalog falls back to its family alias.
        self.assertEqual(self.models.resolve("Opus 5.5"), "opus")
        self.assertEqual(self.models.resolve("main coding agent"), "main")


if __name__ == "__main__":
    unittest.main()

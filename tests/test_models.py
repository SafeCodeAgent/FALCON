"""Tests for reading Claude Code's live model catalog.

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
    doc = {"version": 1, "catalog": {"config": {"models": models}}}
    with open(os.path.join(cache, "cat.json"), "w", encoding="utf-8") as handle:
        json.dump(doc, handle)


SAMPLE = [
    {"id": "claude-opus-5-5", "name": "Opus 5.5", "quick_select": True, "section": "main"},
    {"id": "claude-sonnet-5-5", "name": "Sonnet 5.5", "quick_select": True, "section": "main"},
    {"id": "claude-fable-5-1", "name": "Fable 5.1", "quick_select": True, "section": "main"},
    {"id": "claude-haiku-4-5-20251001", "name": "Haiku 4.5", "quick_select": True, "section": "main"},
    {"id": "claude-opus-5", "name": "Opus 5", "quick_select": False, "section": "overflow"},
]


class ModelCatalogTests(unittest.TestCase):
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
        self.assertIn("Haiku 4.5", names)
        self.assertNotIn("Fable 5.1", names)

    def test_resolve_name_and_alias(self):
        self.assertEqual(self.models.resolve("Opus 5.5"), "claude-opus-5-5")
        self.assertEqual(self.models.resolve("opus"), "claude-opus-5-5")
        self.assertEqual(self.models.resolve("sonnet"), "claude-sonnet-5-5")
        self.assertEqual(self.models.resolve("main coding agent"), "main")

    def test_resolve_rejects_fable_and_unknown(self):
        self.assertIsNone(self.models.resolve("Fable 5.1"))
        self.assertIsNone(self.models.resolve("nonsense"))

    def test_missing_catalog_falls_back_to_alias(self):
        os.environ["CLAUDE_CONFIG_DIR"] = tempfile.mkdtemp()  # no catalog
        import engine.models as models_mod
        reloaded = importlib.reload(models_mod)
        self.assertEqual(reloaded.list_models(), [])
        self.assertEqual(reloaded.resolve("opus"), "opus")


if __name__ == "__main__":
    unittest.main()

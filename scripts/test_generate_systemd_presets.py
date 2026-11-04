#!/usr/bin/env python3
"""Tests for the preset parser in generate-systemd-presets.py.

The parser is the fail-closed core: a malformed preset line must
raise, never silently produce a rule that wrongly credits units at scan
time. Fetching is not covered here (it needs the network); the
generator's --check mode covers the fetch-to-file round trip.

Run:  python3 scripts/test_generate_systemd_presets.py
"""

import importlib.util
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def _load():
    spec = importlib.util.spec_from_file_location(
        "gen_systemd_presets", os.path.join(HERE, "generate-systemd-presets.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gen = _load()


class TestParsePresetFile(unittest.TestCase):
    def test_comments_and_blanks_skipped(self):
        text = (
            "# a comment\n"
            "   ; a semicolon comment\n"
            "\n"
            "enable foo.service\n"
            "   \n"
            "disable bar.socket\n"
        )
        self.assertEqual(
            gen.parse_preset_file(text, "90-test.preset"),
            [("enable", "foo.service"), ("disable", "bar.socket")],
        )

    def test_order_preserved(self):
        text = "enable a.service\ndisable b.service\nenable c.service\n"
        self.assertEqual(
            gen.parse_preset_file(text, "90-test.preset"),
            [
                ("enable", "a.service"),
                ("disable", "b.service"),
                ("enable", "c.service"),
            ],
        )

    def test_instance_list_expands(self):
        text = "enable foo@.service bar baz\n"
        self.assertEqual(
            gen.parse_preset_file(text, "90-test.preset"),
            [("enable", "foo@bar.service"), ("enable", "foo@baz.service")],
        )

    def test_template_without_instances_stays_literal(self):
        text = "enable foo@.service\n"
        self.assertEqual(
            gen.parse_preset_file(text, "90-test.preset"),
            [("enable", "foo@.service")],
        )

    def test_instances_on_non_template_raise(self):
        with self.assertRaises(gen.PresetParseError):
            gen.parse_preset_file("enable foo.service bar\n", "90-test.preset")
        with self.assertRaises(gen.PresetParseError):
            gen.parse_preset_file("enable foo@bar.service baz\n", "90-test.preset")

    def test_unknown_directive_raises(self):
        with self.assertRaises(gen.PresetParseError):
            gen.parse_preset_file("mask foo.service\n", "90-test.preset")

    def test_bare_action_raises(self):
        with self.assertRaises(gen.PresetParseError):
            gen.parse_preset_file("enable\n", "90-test.preset")

    def test_catchall_disable_kept(self):
        self.assertEqual(
            gen.parse_preset_file("disable *\n", "99-test.preset"),
            [("disable", "*")],
        )


class TestSources(unittest.TestCase):
    def test_install_names_sorted_per_flavour(self):
        for flavour, sources in gen.SOURCES.items():
            installs = [install for *_, install in sources]
            self.assertEqual(installs, sorted(installs), flavour)

    def test_render_orders_rules_by_file(self):
        entries = [
            ("90-a.preset", "repo@branch:file (commit x)", [("enable", "a.service")]),
            ("95-b.preset", "repo@branch:file (commit x)", [("disable", "b.service")]),
        ]
        text = gen.render_flavour("opensuse", entries)
        self.assertIn('file = "90-a.preset"', text)
        self.assertLess(
            text.index('pattern = "a.service"'), text.index('pattern = "b.service"')
        )
        self.assertIn("do not edit by hand", text)


if __name__ == "__main__":
    unittest.main()

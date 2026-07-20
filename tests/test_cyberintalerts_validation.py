# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

import unittest

from cyberintalerts_validation import normalize_cve_id


class NormalizeCveIdTestCase(unittest.TestCase):
    def test_accepts_and_normalizes_valid_cve_ids(self):
        self.assertEqual(normalize_cve_id("CVE-2024-1234"), "CVE-2024-1234")
        self.assertEqual(normalize_cve_id("cve-2025-123456"), "CVE-2025-123456")

    def test_rejects_path_and_query_injection(self):
        for value in ("CVE-2024-1234/alerts", "../CVE-2024-1234", "CVE-2024-1234?all=true"):
            with self.subTest(value=value):
                self.assertIsNone(normalize_cve_id(value))

    def test_rejects_invalid_shapes(self):
        for value in ("CVE-24-1234", "CVE-2024-123", "", None, 1234):
            with self.subTest(value=value):
                self.assertIsNone(normalize_cve_id(value))

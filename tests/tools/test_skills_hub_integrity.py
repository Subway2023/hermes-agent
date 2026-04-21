#!/usr/bin/env python3
"""Tests for ClawHub integrity verification in skills_hub.py."""

import hashlib
import io
import unittest
import zipfile
from unittest.mock import patch

from tools.skills_hub import ClawHubSource


def _make_zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, content in files.items():
            zf.writestr(path, content)
    return buf.getvalue()


class _MockResponse:
    def __init__(self, status_code=200, json_data=None, content=b"", text=""):
        self.status_code = status_code
        self._json_data = json_data
        self.content = content
        self.text = text

    def json(self):
        return self._json_data


class TestDownloadZipIntegrity(unittest.TestCase):
    def setUp(self):
        self.src = ClawHubSource()

    @patch("tools.skills_hub.httpx.get")
    def test_hash_match_succeeds(self, mock_get):
        zip_bytes = _make_zip({"SKILL.md": "# Hello"})
        expected = hashlib.sha256(zip_bytes).hexdigest()
        mock_get.return_value = _MockResponse(status_code=200, content=zip_bytes)

        files = self.src._download_zip("test-skill", "1.0.0", expected_sha256=expected)

        self.assertIn("SKILL.md", files)

    @patch("tools.skills_hub.httpx.get")
    def test_hash_mismatch_raises_value_error(self, mock_get):
        zip_bytes = _make_zip({"SKILL.md": "# Tampered"})
        mock_get.return_value = _MockResponse(status_code=200, content=zip_bytes)

        with self.assertRaises(ValueError) as ctx:
            self.src._download_zip("test-skill", "1.0.0", expected_sha256="a" * 64)

        self.assertIn("integrity check failed", str(ctx.exception))

    @patch("tools.skills_hub.httpx.get")
    def test_no_expected_hash_proceeds(self, mock_get):
        zip_bytes = _make_zip({"SKILL.md": "# Hello"})
        mock_get.return_value = _MockResponse(status_code=200, content=zip_bytes)

        files = self.src._download_zip("test-skill", "1.0.0", expected_sha256=None)

        self.assertIn("SKILL.md", files)


class TestExtractFilesIntegrity(unittest.TestCase):
    def setUp(self):
        self.src = ClawHubSource()

    @patch("tools.skills_hub.httpx.get")
    def test_file_hash_match_includes_file(self, mock_get):
        text = "# Skill content"
        expected = hashlib.sha256(text.encode("utf-8")).hexdigest()
        mock_get.return_value = _MockResponse(status_code=200, text=text)

        version_data = {"files": [{"path": "SKILL.md", "rawUrl": "https://files.example/skill-md", "sha256": expected}]}
        files = self.src._extract_files(version_data)

        self.assertIn("SKILL.md", files)
        self.assertEqual(files["SKILL.md"], text)

    @patch("tools.skills_hub.httpx.get")
    def test_file_hash_mismatch_skips_file(self, mock_get):
        mock_get.return_value = _MockResponse(status_code=200, text="# Tampered")

        version_data = {"files": [{"path": "SKILL.md", "rawUrl": "https://files.example/skill-md", "sha256": "b" * 64}]}
        files = self.src._extract_files(version_data)

        self.assertNotIn("SKILL.md", files)

    @patch("tools.skills_hub.httpx.get")
    def test_no_file_hash_proceeds(self, mock_get):
        mock_get.return_value = _MockResponse(status_code=200, text="# Skill content")

        version_data = {"files": [{"path": "SKILL.md", "rawUrl": "https://files.example/skill-md"}]}
        files = self.src._extract_files(version_data)

        self.assertIn("SKILL.md", files)


class TestResolveVersionIntegrity(unittest.TestCase):
    def setUp(self):
        self.src = ClawHubSource()

    @patch("tools.skills_hub.httpx.get")
    def test_returns_sha256_from_version_metadata(self, mock_get):
        mock_get.return_value = _MockResponse(status_code=200, json_data={"sha256hash": "c" * 64, "files": []})

        sha256, version_data = self.src._resolve_version_integrity("test-skill", "1.0.0")

        self.assertEqual(sha256, "c" * 64)
        self.assertIsNotNone(version_data)

    @patch("tools.skills_hub.httpx.get")
    def test_degraded_mode_when_no_sha256(self, mock_get):
        mock_get.return_value = _MockResponse(status_code=200, json_data={"files": []})

        with self.assertLogs("tools.skills_hub", level="WARNING") as log:
            sha256, _ = self.src._resolve_version_integrity("test-skill", "1.0.0")

        self.assertIsNone(sha256)
        self.assertTrue(any("no sha256hash" in line for line in log.output))

    @patch("tools.skills_hub.httpx.get")
    def test_returns_none_when_api_unavailable(self, mock_get):
        mock_get.return_value = _MockResponse(status_code=404)

        sha256, version_data = self.src._resolve_version_integrity("test-skill", "1.0.0")

        self.assertIsNone(sha256)
        self.assertIsNone(version_data)


class TestFetchIntegrity(unittest.TestCase):
    def setUp(self):
        self.src = ClawHubSource()

    @patch("tools.skills_hub.httpx.get")
    def test_fetch_aborts_on_archive_tamper(self, mock_get):
        zip_bytes = _make_zip({"SKILL.md": "# Malicious"})

        def side_effect(url, *args, **kwargs):
            if url.endswith("/skills/test-skill"):
                return _MockResponse(status_code=200, json_data={"slug": "test-skill", "latestVersion": {"version": "1.0.0"}})
            if url.endswith("/skills/test-skill/versions/1.0.0"):
                return _MockResponse(status_code=200, json_data={"sha256hash": "d" * 64, "files": []})
            if url.endswith("/download"):
                return _MockResponse(status_code=200, content=zip_bytes)
            return _MockResponse(status_code=404)

        mock_get.side_effect = side_effect

        result = self.src.fetch("test-skill")

        self.assertIsNone(result)

    @patch("tools.skills_hub.httpx.get")
    def test_fetch_succeeds_with_valid_hash(self, mock_get):
        zip_bytes = _make_zip({"SKILL.md": "# Hello"})
        expected = hashlib.sha256(zip_bytes).hexdigest()

        def side_effect(url, *args, **kwargs):
            if url.endswith("/skills/test-skill"):
                return _MockResponse(status_code=200, json_data={"slug": "test-skill", "latestVersion": {"version": "1.0.0"}})
            if url.endswith("/skills/test-skill/versions/1.0.0"):
                return _MockResponse(status_code=200, json_data={"sha256hash": expected, "files": []})
            if url.endswith("/download"):
                return _MockResponse(status_code=200, content=zip_bytes)
            return _MockResponse(status_code=404)

        mock_get.side_effect = side_effect

        result = self.src.fetch("test-skill")

        self.assertIsNotNone(result)
        self.assertIn("SKILL.md", result.files)

    @patch("tools.skills_hub.httpx.get")
    def test_fetch_proceeds_when_no_hash_published(self, mock_get):
        zip_bytes = _make_zip({"SKILL.md": "# Hello"})

        def side_effect(url, *args, **kwargs):
            if url.endswith("/skills/test-skill"):
                return _MockResponse(status_code=200, json_data={"slug": "test-skill", "latestVersion": {"version": "1.0.0"}})
            if url.endswith("/skills/test-skill/versions/1.0.0"):
                return _MockResponse(status_code=200, json_data={"files": []})
            if url.endswith("/download"):
                return _MockResponse(status_code=200, content=zip_bytes)
            return _MockResponse(status_code=404)

        mock_get.side_effect = side_effect

        with self.assertLogs("tools.skills_hub", level="WARNING"):
            result = self.src.fetch("test-skill")

        self.assertIsNotNone(result)
        self.assertIn("SKILL.md", result.files)


if __name__ == "__main__":
    unittest.main()

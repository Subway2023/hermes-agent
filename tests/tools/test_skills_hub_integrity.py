#!/usr/bin/env python3
"""
Tests for the integrity-verification fix in ClawHubSource (GHSA-3vvq-q2qc-7rmp equivalent).

Covers:
- _download_zip: archive-level SHA-256 check (correct hash / tampered / no hash)
- _extract_files: per-file SHA-256 check (correct hash / tampered / no hash)
- _resolve_version_integrity: extracts sha256hash from version API response
- fetch: end-to-end flow (hash match / hash mismatch / no hash from API)
- bundle_content_hash: full-length digest, path included in hash
"""

import hashlib
import io
import unittest
import zipfile
from unittest.mock import patch

from tools.skills_hub import ClawHubSource, SkillBundle, bundle_content_hash


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_zip(files: dict) -> bytes:
    """Build an in-memory ZIP archive from a {filename: content} dict."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _sha256hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _MockResponse:
    """Minimal httpx-response stand-in used across ClawHub tests."""

    def __init__(self, status_code=200, json_data=None, text="", content=b""):
        self.status_code = status_code
        self._json_data = json_data
        self.text = text
        self.content = content
        self.headers = {}

    def json(self):
        return self._json_data


# ---------------------------------------------------------------------------
# _download_zip integrity tests
# ---------------------------------------------------------------------------

class TestDownloadZipIntegrity(unittest.TestCase):
    def setUp(self):
        self.src = ClawHubSource()
        self.zip_files = {"SKILL.md": "# My Skill\n", "tools.md": "## Tools\n"}
        self.zip_bytes = _make_zip(self.zip_files)
        self.correct_sha256 = _sha256hex(self.zip_bytes)

    @patch("tools.skills_hub.httpx.get")
    def test_accepts_archive_when_hash_matches(self, mock_get):
        mock_get.return_value = _MockResponse(
            status_code=200, content=self.zip_bytes
        )
        files = self.src._download_zip("my-skill", "1.0.0", expected_sha256=self.correct_sha256)
        self.assertIn("SKILL.md", files)
        self.assertIn("tools.md", files)

    @patch("tools.skills_hub.httpx.get")
    def test_rejects_tampered_archive(self, mock_get):
        tampered = _make_zip({"SKILL.md": "# MALICIOUS\n"})
        mock_get.return_value = _MockResponse(
            status_code=200, content=tampered
        )
        with self.assertRaises(ValueError) as ctx:
            self.src._download_zip("my-skill", "1.0.0", expected_sha256=self.correct_sha256)
        self.assertIn("integrity mismatch", str(ctx.exception).lower())
        self.assertIn("my-skill", str(ctx.exception))
        self.assertIn("1.0.0", str(ctx.exception))

    @patch("tools.skills_hub.logger")
    @patch("tools.skills_hub.httpx.get")
    def test_proceeds_with_warning_when_no_hash_provided(self, mock_get, mock_logger):
        mock_get.return_value = _MockResponse(
            status_code=200, content=self.zip_bytes
        )
        # Should NOT raise — degraded mode
        files = self.src._download_zip("my-skill", "1.0.0", expected_sha256=None)
        self.assertIn("SKILL.md", files)
        # A warning must be emitted so the operator can audit unverified installs
        mock_logger.warning.assert_called()
        warning_msg = str(mock_logger.warning.call_args)
        self.assertIn("my-skill", warning_msg)

    @patch("tools.skills_hub.httpx.get")
    def test_returns_empty_dict_on_404(self, mock_get):
        mock_get.return_value = _MockResponse(status_code=404)
        files = self.src._download_zip("missing-skill", "1.0.0", expected_sha256=self.correct_sha256)
        self.assertEqual(files, {})

    @patch("tools.skills_hub.httpx.get")
    def test_returns_empty_dict_on_bad_zip(self, mock_get):
        mock_get.return_value = _MockResponse(
            status_code=200, content=b"not a zip at all"
        )
        files = self.src._download_zip("my-skill", "1.0.0", expected_sha256=_sha256hex(b"not a zip at all"))
        self.assertEqual(files, {})


# ---------------------------------------------------------------------------
# _extract_files per-file integrity tests
# ---------------------------------------------------------------------------

class TestExtractFilesIntegrity(unittest.TestCase):
    def setUp(self):
        self.src = ClawHubSource()

    def _sha256_of_text(self, text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def test_accepts_inline_content_when_hash_matches(self):
        content = "# My Skill\n"
        version_data = {
            "files": [
                {
                    "path": "SKILL.md",
                    "content": content,
                    "sha256": self._sha256_of_text(content),
                }
            ]
        }
        files = self.src._extract_files(version_data)
        self.assertEqual(files["SKILL.md"], content)

    def test_rejects_tampered_inline_content(self):
        version_data = {
            "files": [
                {
                    "path": "SKILL.md",
                    "content": "# MALICIOUS\n",
                    "sha256": self._sha256_of_text("# Legitimate content\n"),
                }
            ]
        }
        with self.assertRaises(ValueError) as ctx:
            self.src._extract_files(version_data)
        self.assertIn("integrity mismatch", str(ctx.exception).lower())
        self.assertIn("SKILL.md", str(ctx.exception))

    @patch("tools.skills_hub.logger")
    def test_proceeds_without_per_file_hash(self, mock_logger):
        version_data = {
            "files": [
                {"path": "SKILL.md", "content": "# My Skill\n"}
                # no "sha256" key
            ]
        }
        files = self.src._extract_files(version_data)
        self.assertIn("SKILL.md", files)
        # A debug log must be emitted for auditability
        mock_logger.debug.assert_called()

    @patch("tools.skills_hub.httpx.get")
    def test_accepts_remote_file_when_hash_matches(self, mock_get):
        content = "# My Skill\n"
        mock_get.return_value = _MockResponse(
            status_code=200, content=content.encode("utf-8"), text=content
        )
        version_data = {
            "files": [
                {
                    "path": "SKILL.md",
                    "rawUrl": "https://cdn.example.com/SKILL.md",
                    "sha256": self._sha256_of_text(content),
                }
            ]
        }
        files = self.src._extract_files(version_data)
        self.assertEqual(files["SKILL.md"], content)

    @patch("tools.skills_hub.httpx.get")
    def test_rejects_tampered_remote_file(self, mock_get):
        legitimate_content = "# Legitimate\n"
        tampered_content = "# MALICIOUS\n"
        mock_get.return_value = _MockResponse(
            status_code=200,
            content=tampered_content.encode("utf-8"),
            text=tampered_content,
        )
        version_data = {
            "files": [
                {
                    "path": "SKILL.md",
                    "rawUrl": "https://cdn.example.com/SKILL.md",
                    "sha256": self._sha256_of_text(legitimate_content),
                }
            ]
        }
        with self.assertRaises(ValueError) as ctx:
            self.src._extract_files(version_data)
        self.assertIn("integrity mismatch", str(ctx.exception).lower())


# ---------------------------------------------------------------------------
# _resolve_version_integrity tests
# ---------------------------------------------------------------------------

class TestResolveVersionIntegrity(unittest.TestCase):
    def setUp(self):
        self.src = ClawHubSource()

    @patch("tools.skills_hub.httpx.get")
    def test_extracts_plain_hex_sha256hash(self, mock_get):
        expected_hex = "a" * 64
        mock_get.return_value = _MockResponse(
            status_code=200,
            json_data={"sha256hash": expected_hex, "files": []},
        )
        sha256, _ = self.src._resolve_version_integrity("my-skill", "1.0.0")
        self.assertEqual(sha256, expected_hex)

    @patch("tools.skills_hub.httpx.get")
    def test_strips_sha256_prefix(self, mock_get):
        hex_val = "b" * 64
        mock_get.return_value = _MockResponse(
            status_code=200,
            json_data={"sha256hash": f"sha256:{hex_val}"},
        )
        sha256, _ = self.src._resolve_version_integrity("my-skill", "1.0.0")
        self.assertEqual(sha256, hex_val)

    @patch("tools.skills_hub.httpx.get")
    def test_extracts_sha256hash_from_nested_version_key(self, mock_get):
        hex_val = "c" * 64
        mock_get.return_value = _MockResponse(
            status_code=200,
            json_data={"version": {"sha256hash": hex_val, "version": "1.0.0"}},
        )
        sha256, _ = self.src._resolve_version_integrity("my-skill", "1.0.0")
        self.assertEqual(sha256, hex_val)

    @patch("tools.skills_hub.httpx.get")
    def test_returns_none_when_sha256hash_absent(self, mock_get):
        mock_get.return_value = _MockResponse(
            status_code=200,
            json_data={"files": [{"path": "SKILL.md", "sha256": "d" * 64}]},
        )
        sha256, version_data = self.src._resolve_version_integrity("my-skill", "1.0.0")
        self.assertIsNone(sha256)
        self.assertIsNotNone(version_data)

    @patch("tools.skills_hub.httpx.get")
    def test_returns_none_none_when_api_fails(self, mock_get):
        mock_get.return_value = _MockResponse(status_code=404, json_data=None)
        sha256, version_data = self.src._resolve_version_integrity("my-skill", "1.0.0")
        self.assertIsNone(sha256)
        self.assertIsNone(version_data)

    @patch("tools.skills_hub.httpx.get")
    def test_rejects_truncated_sha256hash(self, mock_get):
        # 16-char truncated hash must NOT be accepted as a valid integrity hash
        mock_get.return_value = _MockResponse(
            status_code=200,
            json_data={"sha256hash": "abcdef0123456789"},  # only 16 chars
        )
        sha256, _ = self.src._resolve_version_integrity("my-skill", "1.0.0")
        self.assertIsNone(sha256)


# ---------------------------------------------------------------------------
# fetch end-to-end integrity tests
# ---------------------------------------------------------------------------

class TestFetchIntegrity(unittest.TestCase):
    def setUp(self):
        self.src = ClawHubSource()
        self.zip_files = {"SKILL.md": "# My Skill\n"}
        self.zip_bytes = _make_zip(self.zip_files)
        self.correct_sha256 = _sha256hex(self.zip_bytes)

    def _side_effect_with_zip(self, sha256_in_api=None, zip_content=None):
        """Return a mock side_effect function for httpx.get."""
        if zip_content is None:
            zip_content = self.zip_bytes

        def side_effect(url, **_kwargs):
            if url.endswith("/skills/my-skill"):
                return _MockResponse(
                    status_code=200,
                    json_data={"slug": "my-skill", "latestVersion": {"version": "1.0.0"}},
                )
            if url.endswith("/skills/my-skill/versions/1.0.0"):
                data = {}
                if sha256_in_api:
                    data["sha256hash"] = sha256_in_api
                return _MockResponse(status_code=200, json_data=data)
            if "/download" in url:
                return _MockResponse(status_code=200, content=zip_content)
            return _MockResponse(status_code=404, json_data={})

        return side_effect

    @patch("tools.skills_hub.httpx.get")
    def test_fetch_succeeds_when_hash_matches(self, mock_get):
        mock_get.side_effect = self._side_effect_with_zip(sha256_in_api=self.correct_sha256)
        bundle = self.src.fetch("my-skill")
        self.assertIsNotNone(bundle)
        self.assertEqual(bundle.name, "my-skill")
        self.assertIn("SKILL.md", bundle.files)

    @patch("tools.skills_hub.logger")
    @patch("tools.skills_hub.httpx.get")
    def test_fetch_returns_none_when_hash_mismatches(self, mock_get, mock_logger):
        tampered = _make_zip({"SKILL.md": "# MALICIOUS\n"})
        mock_get.side_effect = self._side_effect_with_zip(
            sha256_in_api=self.correct_sha256,
            zip_content=tampered,
        )
        bundle = self.src.fetch("my-skill")
        self.assertIsNone(bundle)
        mock_logger.warning.assert_called()
        warning_msg = str(mock_logger.warning.call_args)
        self.assertIn("integrity", warning_msg.lower())

    @patch("tools.skills_hub.logger")
    @patch("tools.skills_hub.httpx.get")
    def test_fetch_warns_and_returns_bundle_when_no_hash_from_api(self, mock_get, mock_logger):
        # API returns no sha256hash — degraded mode, install proceeds with warning
        mock_get.side_effect = self._side_effect_with_zip(sha256_in_api=None)
        bundle = self.src.fetch("my-skill")
        self.assertIsNotNone(bundle)
        self.assertIn("SKILL.md", bundle.files)
        mock_logger.warning.assert_called()

    @patch("tools.skills_hub.httpx.get")
    def test_fetch_returns_none_when_skill_not_found(self, mock_get):
        mock_get.return_value = _MockResponse(status_code=404, json_data=None)
        bundle = self.src.fetch("nonexistent-skill")
        self.assertIsNone(bundle)


# ---------------------------------------------------------------------------
# bundle_content_hash tests
# ---------------------------------------------------------------------------

class TestBundleContentHash(unittest.TestCase):
    def _bundle(self, files: dict) -> SkillBundle:
        return SkillBundle(
            name="test",
            files=files,
            source="clawhub",
            identifier="test",
            trust_level="community",
        )

    def test_hash_is_full_64_char_hex(self):
        h = bundle_content_hash(self._bundle({"SKILL.md": "# test\n"}))
        self.assertTrue(h.startswith("sha256:"))
        digest = h[len("sha256:"):]
        self.assertEqual(len(digest), 64)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_hash_is_not_truncated(self):
        # Previous implementation used hexdigest()[:16]; ensure that is fixed
        h = bundle_content_hash(self._bundle({"SKILL.md": "# test\n"}))
        digest = h[len("sha256:"):]
        self.assertGreater(len(digest), 16, "Hash must not be truncated to 16 chars")

    def test_same_bundle_produces_same_hash(self):
        b = self._bundle({"SKILL.md": "# test\n", "tools.md": "## tools\n"})
        self.assertEqual(bundle_content_hash(b), bundle_content_hash(b))

    def test_content_change_changes_hash(self):
        h1 = bundle_content_hash(self._bundle({"SKILL.md": "# original\n"}))
        h2 = bundle_content_hash(self._bundle({"SKILL.md": "# modified\n"}))
        self.assertNotEqual(h1, h2)

    def test_path_rename_changes_hash(self):
        # Path is included in the hash, so renaming a file must change the digest
        h1 = bundle_content_hash(self._bundle({"SKILL.md": "# content\n"}))
        h2 = bundle_content_hash(self._bundle({"RENAMED.md": "# content\n"}))
        self.assertNotEqual(h1, h2)

    def test_file_addition_changes_hash(self):
        h1 = bundle_content_hash(self._bundle({"SKILL.md": "# content\n"}))
        h2 = bundle_content_hash(self._bundle({"SKILL.md": "# content\n", "extra.md": "extra\n"}))
        self.assertNotEqual(h1, h2)

    def test_hash_is_deterministic_regardless_of_dict_insertion_order(self):
        b1 = self._bundle({"SKILL.md": "a", "tools.md": "b"})
        b2 = self._bundle({"tools.md": "b", "SKILL.md": "a"})
        self.assertEqual(bundle_content_hash(b1), bundle_content_hash(b2))


if __name__ == "__main__":
    unittest.main()

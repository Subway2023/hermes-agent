"""Tests for GNU long-option abbreviation bypass in DANGEROUS_PATTERNS.

GNU tools accept unique long-option prefix abbreviations at runtime
(e.g. `rm --recur` resolves to `rm --recursive`).  Patterns that only
matched the full flag name could be bypassed by passing a valid abbreviation
that the regex did not cover.

Affected patterns and their minimum distinguishing prefix:
  rm/chmod/chown  --recursive  →  --recur[a-z]*
  sed             --in-place   →  --in-plac[a-z]*
  git push        --force      →  --forc[a-z]*
"""

import pytest

from tools.approval import detect_dangerous_command


class TestRmRecursiveLongOptionAbbreviation:
    """rm --recur* abbreviations must be caught just like --recursive."""

    def test_rm_recursive_full_still_detected(self):
        dangerous, _, desc = detect_dangerous_command("rm --recursive /tmp/dir")
        assert dangerous is True
        assert "delete" in desc.lower()

    def test_rm_recur_abbreviation_detected(self):
        dangerous, _, desc = detect_dangerous_command("rm --recur /home/user")
        assert dangerous is True, "rm --recur is a valid abbreviation of --recursive"
        assert "delete" in desc.lower()

    def test_rm_recurs_abbreviation_detected(self):
        dangerous, _, desc = detect_dangerous_command("rm --recurs /home/user")
        assert dangerous is True

    def test_rm_recursi_abbreviation_detected(self):
        dangerous, _, desc = detect_dangerous_command("rm --recursi /var/log")
        assert dangerous is True

    def test_rm_recursiv_abbreviation_detected(self):
        dangerous, _, desc = detect_dangerous_command("rm --recursiv /var/log")
        assert dangerous is True

    def test_rm_regular_file_not_flagged(self):
        dangerous, _, _ = detect_dangerous_command("rm ./file.txt")
        assert dangerous is False


class TestChmodRecursiveLongOptionAbbreviation:
    """chmod --recur* abbreviations with dangerous permissions must be caught."""

    def test_chmod_recursive_full_still_detected(self):
        dangerous, _, desc = detect_dangerous_command("chmod --recursive 777 /var")
        assert dangerous is True
        assert "writable" in desc.lower() or "permission" in desc.lower()

    def test_chmod_recur_777_detected(self):
        dangerous, _, desc = detect_dangerous_command("chmod --recur 777 /etc/")
        assert dangerous is True, "chmod --recur 777 is a valid abbreviation of --recursive"

    def test_chmod_recurs_666_detected(self):
        dangerous, _, desc = detect_dangerous_command("chmod --recurs 666 /srv")
        assert dangerous is True

    def test_chmod_recur_o_plus_w_detected(self):
        dangerous, _, desc = detect_dangerous_command("chmod --recur o+w /home")
        assert dangerous is True

    def test_chmod_recur_safe_permissions_not_flagged(self):
        """--recur with non-dangerous permissions (e.g. 755) must not be flagged."""
        dangerous, _, _ = detect_dangerous_command("chmod --recur 755 /opt/app")
        assert dangerous is False


class TestChownRecursiveLongOptionAbbreviation:
    """chown --recur* abbreviations targeting root must be caught."""

    def test_chown_recursive_full_still_detected(self):
        dangerous, _, desc = detect_dangerous_command("chown --recursive root /etc")
        assert dangerous is True
        assert "chown" in desc.lower() or "root" in desc.lower()

    def test_chown_recur_root_detected(self):
        dangerous, _, desc = detect_dangerous_command("chown --recur root /etc")
        assert dangerous is True, "chown --recur root is a valid abbreviation of --recursive"

    def test_chown_recurs_root_detected(self):
        dangerous, _, _ = detect_dangerous_command("chown --recurs root:root /var")
        assert dangerous is True

    def test_chown_recur_non_root_not_flagged(self):
        """--recur* chown to a non-root user must not be flagged."""
        dangerous, _, _ = detect_dangerous_command("chown --recur nobody /opt/app")
        assert dangerous is False


class TestSedInPlaceLongOptionAbbreviation:
    """sed --in-plac* abbreviations writing to /etc must be caught."""

    def test_sed_in_place_full_still_detected(self):
        dangerous, _, desc = detect_dangerous_command(
            "sed --in-place 's/old/new/' /etc/hosts"
        )
        assert dangerous is True
        assert "system config" in desc.lower() or "in-place" in desc.lower()

    def test_sed_in_plac_abbreviation_detected(self):
        dangerous, _, desc = detect_dangerous_command(
            "sed --in-plac 's/foo/bar/' /etc/passwd"
        )
        assert dangerous is True, "sed --in-plac is a valid abbreviation of --in-place"

    def test_sed_in_place_safe_path_not_flagged(self):
        """--in-place on a non-/etc path must not be flagged."""
        dangerous, _, _ = detect_dangerous_command(
            "sed --in-place 's/old/new/' /tmp/config.txt"
        )
        assert dangerous is False

    def test_sed_short_i_flag_still_detected(self):
        """Existing -i pattern must not regress."""
        dangerous, _, _ = detect_dangerous_command("sed -i 's/x/y/' /etc/passwd")
        assert dangerous is True


class TestGitPushForceLongOptionAbbreviation:
    """git push --forc* abbreviations must be caught."""

    def test_git_push_force_full_still_detected(self):
        dangerous, _, desc = detect_dangerous_command("git push --force origin main")
        assert dangerous is True
        assert "force" in desc.lower()

    def test_git_push_forc_abbreviation_detected(self):
        dangerous, _, desc = detect_dangerous_command("git push --forc origin main")
        assert dangerous is True, "git push --forc is a valid abbreviation of --force"

    def test_git_push_forced_variant_detected(self):
        """--forced (hypothetical) must also be caught by the prefix match."""
        dangerous, _, _ = detect_dangerous_command("git push --forced origin main")
        assert dangerous is True

    def test_git_push_short_f_still_detected(self):
        """Existing -f pattern must not regress."""
        dangerous, _, _ = detect_dangerous_command("git push -f origin main")
        assert dangerous is True

    def test_git_push_no_force_not_flagged(self):
        dangerous, _, _ = detect_dangerous_command("git push origin main")
        assert dangerous is False

    def test_git_push_upstream_not_flagged(self):
        dangerous, _, _ = detect_dangerous_command("git push --set-upstream origin feature")
        assert dangerous is False


class TestFullFormRegressions:
    """All full-form long flags must still be detected after the prefix change."""

    @pytest.mark.parametrize("cmd", [
        "rm --recursive /important",
        "chmod --recursive 777 /etc",
        "chown --recursive root /etc",
        "sed --in-place 's/x/y/' /etc/passwd",
        "git push --force origin main",
    ])
    def test_full_form_still_detected(self, cmd):
        dangerous, key, _ = detect_dangerous_command(cmd)
        assert dangerous is True, f"Full-form long flag not detected in: {cmd!r}"
        assert key is not None

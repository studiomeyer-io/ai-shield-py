"""NFKD + zero-width + combining-mark + homoglyph normalization tests.

Covers the bypass classes documented in REVIEW.md F3:
  - homoglyph substitution (Cyrillic / Greek look-alikes)
  - zero-width insertion (U+200B / U+200C / U+200D / U+2060 / U+FEFF)
  - combining-mark stacking (U+0300-U+036F)
  - NFKD compatibility (full-width, mathematical bold, ligatures)
"""

from __future__ import annotations

import pytest

from ai_shield.scanner.heuristic import (
    COMBINING_RE,
    HOMOGLYPH_MAP,
    ZERO_WIDTH_RE,
    normalize,
)


class TestZeroWidthStrip:
    @pytest.mark.parametrize("ch", ["\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"])
    def test_each_zero_width_character_is_removed(self, ch: str) -> None:
        assert normalize(f"sys{ch}tem") == "system"

    def test_multiple_zero_widths_in_sequence(self) -> None:
        assert normalize("i\u200bg\u200cn\u200do\u2060r\ufeffe") == "ignore"

    def test_zero_width_at_string_boundaries(self) -> None:
        assert normalize("\u200bignore\u200b") == "ignore"

    def test_regex_matches_only_listed_codepoints(self) -> None:
        for ch in ["\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"]:
            assert ZERO_WIDTH_RE.match(ch)
        assert not ZERO_WIDTH_RE.match("a")
        assert not ZERO_WIDTH_RE.match(" ")


class TestCombiningMarkStrip:
    def test_diacritic_combining_mark_removed(self) -> None:
        # "n" + combining tilde (U+0303) → after NFKD then strip combining → "n"
        assert normalize("n\u0303ot") == "not"

    def test_stacked_combining_marks(self) -> None:
        # 5 stacked combining marks
        attack = "i" + "\u0301\u0302\u0303\u0304\u0305" + "gnore"
        assert normalize(attack) == "ignore"

    def test_combining_mark_regex_range(self) -> None:
        for codepoint in [0x0300, 0x0320, 0x036F]:
            assert COMBINING_RE.match(chr(codepoint))
        assert not COMBINING_RE.match(chr(0x0299))
        assert not COMBINING_RE.match(chr(0x0370))


class TestHomoglyphSubstitution:
    def test_cyrillic_a_mapped_to_latin_a(self) -> None:
        # Cyrillic 'а' (U+0430) → Latin 'a'
        assert normalize("\u0430bc") == "abc"

    def test_full_cyrillic_word_normalized(self) -> None:
        # All Cyrillic look-alikes for "system"
        cyrillic_system = "\u0455\u0443\u0455t\u0435\u043c"  # ѕуѕtем
        out = normalize(cyrillic_system)
        assert out == "system"

    def test_greek_alpha_mapped(self) -> None:
        assert normalize("\u03b1ttack") == "attack"

    def test_homoglyph_map_size_matches_expectation(self) -> None:
        # Locks the catalogue size against accidental drift.
        assert len(HOMOGLYPH_MAP) == 49

    def test_unknown_unicode_passes_through(self) -> None:
        # 漢字 has no entry — must survive normalization.
        assert "漢" in normalize("漢字")


class TestNFKD:
    def test_full_width_letters_normalized(self) -> None:
        # 'ＳＹＳＴＥＭ' → 'SYSTEM' under NFKD
        out = normalize("ＳＹＳＴＥＭ")
        assert out == "SYSTEM"

    def test_ligature_decomposed(self) -> None:
        # ﬁ → fi
        assert normalize("ﬁle") == "file"

    def test_mathematical_bold_letters_decomposed(self) -> None:
        # 𝐢𝐠𝐧𝐨𝐫𝐞 (mathematical bold ignore) → ignore
        bold = "\U0001d422\U0001d420\U0001d427\U0001d428\U0001d42b\U0001d41e"
        assert normalize(bold) == "ignore"


class TestCombinedAttacks:
    def test_homoglyph_plus_zero_width(self) -> None:
        # Cyrillic 'а' + ZWSP → 'a'
        assert normalize("\u0430\u200bttack") == "attack"

    def test_homoglyph_plus_combining(self) -> None:
        # Cyrillic 'а' + combining acute + 'ttack' → 'attack'
        assert normalize("\u0430\u0301ttack") == "attack"

    def test_full_attack_chain(self) -> None:
        # NFKD + zero-width + combining + homoglyph in one input
        attack = "ＩＧＮＯ\u200b\u0301\u0430\u0440\u0435"
        out = normalize(attack)
        assert out == "IGNOape"  # demonstrates layered transformations

    def test_idempotent_on_clean_ascii(self) -> None:
        clean = "the quick brown fox"
        assert normalize(clean) == clean

    def test_empty_string(self) -> None:
        assert normalize("") == ""

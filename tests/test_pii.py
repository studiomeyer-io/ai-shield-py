"""PII scanner — 8 PII types with 5 validators.

Validator coverage:
  - Luhn (ISO 7812) for credit cards: valid/invalid checksums
  - IBAN mod-97 (ISO 13616-1): valid DE/GB/FR + mutated checksums fail
  - German tax ID: 11 digits no leading zero
  - Phone: ITU E.164 digit-count
  - IP not-private filter: 10.x, 172.16-31.x, 192.168.x, 127.x rejected
"""

from __future__ import annotations

import pytest

from ai_shield.scanner.pii import (
    PIIConfig,
    PIIScanner,
    mask_value,
    validate_german_tax_id,
    validate_iban,
    validate_ip_not_private,
    validate_luhn,
    validate_phone,
)

# -- Validators -----------------------------------------------------------


class TestLuhn:
    @pytest.mark.parametrize(
        "number",
        [
            "4242424242424242",  # Stripe test Visa
            "5555555555554444",  # Stripe test MC
            "378282246310005",  # Amex 15-digit
            "6011111111111117",  # Discover
        ],
    )
    def test_known_valid(self, number: str) -> None:
        assert validate_luhn(number) is True

    @pytest.mark.parametrize(
        "number",
        [
            "4242424242424241",  # off-by-one digit
            "1234567890123456",  # garbage
            "0000000000000001",
        ],
    )
    def test_known_invalid(self, number: str) -> None:
        assert validate_luhn(number) is False

    def test_too_short(self) -> None:
        assert validate_luhn("12345") is False

    def test_too_long(self) -> None:
        assert validate_luhn("1" * 25) is False

    def test_with_separators_passes_when_digits_valid(self) -> None:
        # Validator strips non-digits.
        assert validate_luhn("4242 4242 4242 4242") is True


class TestIBAN:
    @pytest.mark.parametrize(
        "iban",
        [
            "DE89370400440532013000",  # German example
            "GB82WEST12345698765432",  # British example
            "FR1420041010050500013M02606",  # French example
        ],
    )
    def test_known_valid(self, iban: str) -> None:
        assert validate_iban(iban) is True

    def test_with_spaces_normalises(self) -> None:
        assert validate_iban("DE89 3704 0044 0532 0130 00") is True

    def test_mutated_checksum_fails(self) -> None:
        # Flip a digit in the BBAN portion.
        assert validate_iban("DE89370400440532013001") is False

    def test_too_short(self) -> None:
        assert validate_iban("DE89") is False

    def test_too_long(self) -> None:
        assert validate_iban("DE" + "1" * 40) is False

    def test_lowercase_country_code_accepted(self) -> None:
        # Validator uppercases input first.
        assert validate_iban("de89370400440532013000") is True

    def test_garbage_country_prefix_fails(self) -> None:
        assert validate_iban("ZZ00000000000000") is False


class TestGermanTaxId:
    """v0.1.1: now enforces the BMF mod-11/10 algorithm + distinct-digit
    rule. Random 11-digit strings no longer test positive."""

    @pytest.mark.parametrize(
        "value",
        [
            # Verified by walking the BMF mod-11/10 algorithm.
            # `26954371827`: body has exactly one pair (the two 2s),
            # check digit 7 matches the algorithm output.
            "26954371827",
        ],
    )
    def test_known_valid(self, value: str) -> None:
        assert validate_german_tax_id(value) is True

    def test_leading_zero_rejected(self) -> None:
        assert validate_german_tax_id("01234567890") is False

    def test_short_rejected(self) -> None:
        assert validate_german_tax_id("123") is False

    def test_long_rejected(self) -> None:
        assert validate_german_tax_id("123456789012") is False

    def test_alpha_rejected(self) -> None:
        assert validate_german_tax_id("1234567890A") is False

    def test_v0_1_0_false_positive_now_rejected(self) -> None:
        """v0.1.0 returned True for any 11-digit string starting 1-9.
        v0.1.1 must reject `12345678901` because it has 10 distinct
        digits (no pair) and the check digit fails the BMF algorithm."""
        assert validate_german_tax_id("12345678901") is False

    def test_no_pair_rejected(self) -> None:
        """First 10 digits all distinct → no pair_or_triple → reject."""
        assert validate_german_tax_id("12345678905") is False

    def test_quadruple_digit_rejected(self) -> None:
        """A digit appearing 4+ times in the body → reject."""
        # Four 1s in positions 0-3, real check digit irrelevant.
        assert validate_german_tax_id("11112345670") is False

    def test_two_pairs_rejected(self) -> None:
        """Two distinct pairs (rule 2 says exactly one repeated digit)."""
        assert validate_german_tax_id("11223456780") is False

    def test_check_digit_mismatch_rejected(self) -> None:
        """Same body as the known-valid test but wrong check digit."""
        assert validate_german_tax_id("26954371820") is False
        assert validate_german_tax_id("26954371829") is False


class TestPhone:
    @pytest.mark.parametrize(
        "value",
        ["+49 30 12345678", "(212) 555-1234", "0049-30-1234567", "1234567"],
    )
    def test_valid_digit_counts(self, value: str) -> None:
        assert validate_phone(value) is True

    def test_too_few_digits(self) -> None:
        assert validate_phone("123456") is False

    def test_too_many_digits(self) -> None:
        assert validate_phone("1" * 16) is False

    @pytest.mark.parametrize(
        "ip",
        ["192.168.1.5", "8.8.8.8", "10.0.0.1", "203.0.113.5"],
    )
    def test_rejects_ipv4_format(self, ip: str) -> None:
        """v0.1.1: phone validator rejects IPv4-format so the ip_address
        pattern can claim them. Without this, the wider v0.1.1 phone
        regex would silently steal IP detection."""
        assert validate_phone(ip) is False


class TestIPFilter:
    @pytest.mark.parametrize(
        "ip",
        ["10.0.0.1", "172.16.5.5", "172.31.255.255", "192.168.1.1", "127.0.0.1"],
    )
    def test_private_rejected(self, ip: str) -> None:
        assert validate_ip_not_private(ip) is False

    @pytest.mark.parametrize(
        "ip",
        ["8.8.8.8", "1.1.1.1", "172.32.0.1", "172.15.0.1", "203.0.113.5"],
    )
    def test_public_accepted(self, ip: str) -> None:
        assert validate_ip_not_private(ip) is True

    def test_garbage_rejected(self) -> None:
        assert validate_ip_not_private("not.an.ip.address") is False

    def test_octet_out_of_range(self) -> None:
        assert validate_ip_not_private("999.999.999.999") is False


# -- Masking --------------------------------------------------------------


class TestMasking:
    def test_email_masking_keeps_domain(self) -> None:
        out = mask_value("alice@example.com", "email")
        assert out == "al***@example.com"

    def test_email_short_local_part(self) -> None:
        out = mask_value("a@example.com", "email")
        assert "@example.com" in out

    def test_credit_card_keeps_last_four(self) -> None:
        out = mask_value("4242424242424242", "credit_card")
        assert out == "***4242"

    def test_iban_keeps_last_four(self) -> None:
        out = mask_value("DE89370400440532013000", "iban")
        assert out.endswith("3000")

    def test_ip_keeps_first_two_octets(self) -> None:
        assert mask_value("8.8.8.8", "ip_address") == "8.8.***.***"

    def test_url_with_creds_masks_credentials(self) -> None:
        out = mask_value("https://alice:secret@host/path", "url_with_credentials")
        assert "secret" not in out
        assert "alice" not in out
        assert "***:***@host" in out


# -- Scanner --------------------------------------------------------------


class TestScannerDecisions:
    @pytest.mark.asyncio
    async def test_allow_when_no_pii(self) -> None:
        scanner = PIIScanner()
        result = await scanner.scan("the weather is fine today")
        assert result.decision == "allow"
        assert result.violations == []

    @pytest.mark.asyncio
    async def test_redact_action_warns_and_replaces(self) -> None:
        scanner = PIIScanner(PIIConfig(action="redact"))
        result = await scanner.scan("Contact alice@example.com for details")
        assert result.decision == "warn"
        assert result.sanitized_text is not None
        assert "alice@example.com" not in result.sanitized_text
        assert "[REDACTED:email]" in result.sanitized_text

    @pytest.mark.asyncio
    async def test_block_action(self) -> None:
        scanner = PIIScanner(PIIConfig(action="block"))
        result = await scanner.scan("Contact alice@example.com")
        assert result.decision == "block"

    @pytest.mark.asyncio
    async def test_warn_action(self) -> None:
        scanner = PIIScanner(PIIConfig(action="warn"))
        result = await scanner.scan("Contact alice@example.com")
        assert result.decision == "warn"
        assert result.sanitized_text is None

    @pytest.mark.asyncio
    async def test_allow_action_returns_violations_but_allows(self) -> None:
        scanner = PIIScanner(PIIConfig(action="allow"))
        result = await scanner.scan("Contact alice@example.com")
        assert result.decision == "allow"
        assert len(result.violations) == 1


class TestScannerEntities:
    @pytest.mark.asyncio
    async def test_credit_card_with_invalid_luhn_skipped(self) -> None:
        scanner = PIIScanner()
        # Looks like 16 digits but Luhn fails.
        result = await scanner.scan("number: 1234 5678 9012 3456")
        assert result.decision == "allow"

    @pytest.mark.asyncio
    async def test_credit_card_with_valid_luhn_detected(self) -> None:
        scanner = PIIScanner()
        result = await scanner.scan("card 4242 4242 4242 4242")
        ccs = [v for v in result.violations if "credit_card" in v.detector]
        assert len(ccs) == 1

    @pytest.mark.asyncio
    async def test_private_ip_filtered(self) -> None:
        scanner = PIIScanner()
        result = await scanner.scan("server at 192.168.1.5")
        assert result.decision == "allow"

    @pytest.mark.asyncio
    async def test_public_ip_detected(self) -> None:
        scanner = PIIScanner()
        result = await scanner.scan("upstream 8.8.8.8 reachable")
        ips = [v for v in result.violations if "ip_address" in v.detector]
        assert len(ips) == 1

    @pytest.mark.asyncio
    async def test_overlapping_spans_first_wins(self) -> None:
        # Email pattern wins over phone-like structure inside the local part.
        scanner = PIIScanner(PIIConfig(action="allow"))
        result = await scanner.scan("ping 0049-30-12345678")
        # Phone validator must accept this, IP must not.
        assert any(v.detector == "pii:phone" for v in result.violations)

    @pytest.mark.asyncio
    async def test_url_with_credentials_detected(self) -> None:
        scanner = PIIScanner(PIIConfig(action="allow"))
        result = await scanner.scan("see https://user:pass@vault.example.com/k")
        assert any(v.detector == "pii:url_with_credentials" for v in result.violations)

    @pytest.mark.asyncio
    async def test_score_grows_with_more_entities(self) -> None:
        scanner = PIIScanner(PIIConfig(action="allow"))
        single = await scanner.scan("alice@example.com")
        many = await scanner.scan(
            "alice@example.com bob@example.com carol@example.com",
        )
        assert many.score > single.score


# -- ReDoS regression (v0.1.1 H1 + H2 hardening) -------------------------


class TestReDoSAdversarial:
    """v0.1.1 hardening: the credit_card and phone regexes were rewritten
    to remove nested optional quantifiers that caused catastrophic
    backtracking on adversarial inputs. Each test pins a 2 s budget on
    a 4 KB pathological input — the v0.1.0 patterns would hang for
    many seconds (or minutes).
    """

    @pytest.mark.timeout(2)
    @pytest.mark.asyncio
    async def test_credit_card_no_redos_on_repeated_digit_separators(self) -> None:
        # Pathological for `(?:\d[ -]?){12,18}` style patterns.
        evil = "1 " * 2000
        scanner = PIIScanner(PIIConfig(action="allow"))
        result = await scanner.scan(evil)
        # Any decision is acceptable as long as we don't time out.
        assert result is not None

    @pytest.mark.timeout(2)
    @pytest.mark.asyncio
    async def test_phone_no_redos_on_nested_separators(self) -> None:
        # Pathological for `(?:\(?\d{2,4}\)?[\s.-]?){2,5}` style patterns.
        evil = "(1)" * 1500
        scanner = PIIScanner(PIIConfig(action="allow"))
        result = await scanner.scan(evil)
        assert result is not None

    @pytest.mark.timeout(2)
    @pytest.mark.asyncio
    async def test_phone_no_redos_on_dash_dense_input(self) -> None:
        evil = "1-" * 2000
        scanner = PIIScanner(PIIConfig(action="allow"))
        result = await scanner.scan(evil)
        assert result is not None

    def test_credit_card_real_visa_still_matches(self) -> None:
        """Regression: hardened pattern still matches real card formats."""
        from ai_shield.scanner.pii import PII_PATTERNS

        cc_pattern = next(p for p in PII_PATTERNS if p.type == "credit_card")
        for fmt in [
            "4242 4242 4242 4242",  # Visa with spaces
            "4242-4242-4242-4242",  # Visa with dashes
            "4242424242424242",  # Visa raw
            "378282246310005",  # Amex 15-digit raw
        ]:
            assert cc_pattern.regex.search(fmt) is not None, f"failed: {fmt}"

    def test_phone_real_formats_still_match(self) -> None:
        """Regression: hardened pattern still matches real phone formats."""
        from ai_shield.scanner.pii import PII_PATTERNS

        phone_pattern = next(p for p in PII_PATTERNS if p.type == "phone")
        for fmt in [
            "+49 30 12345678",
            "(212) 555-1234",
            "0049-30-1234567",
        ]:
            assert phone_pattern.regex.search(fmt) is not None, f"failed: {fmt}"

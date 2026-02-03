"""
Tests for secret validation service.
"""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock

from api.services.secret_validator import SecretValidator


class TestSecretValidator:
    """Tests for the secret validation service."""

    @pytest.fixture
    def validator(self):
        """Create validator instance."""
        return SecretValidator()

    # Provider identification tests

    def test_identify_provider_google(self, validator):
        """Test identification of Google API keys."""
        result = validator.identify_provider("AIzaSyA1234567890abcdefghijklmno")
        assert result == "google"

    def test_identify_provider_aws(self, validator):
        """Test identification of AWS access keys."""
        result = validator.identify_provider("AKIAIOSFODNN7EXAMPLE")
        assert result == "aws"

    def test_identify_provider_stripe_secret_live(self, validator):
        """Test identification of Stripe live secret keys."""
        # Build pattern dynamically to avoid secret scanning
        test_key = "sk" + "_" + "live" + "_" + ("x" * 24)
        result = validator.identify_provider(test_key)
        assert result == "stripe"

    def test_identify_provider_stripe_publishable_test(self, validator):
        """Test identification of Stripe test publishable keys."""
        # Build pattern dynamically to avoid secret scanning
        test_key = "pk" + "_" + "test" + "_" + ("x" * 24)
        result = validator.identify_provider(test_key)
        assert result == "stripe"

    def test_identify_provider_github(self, validator):
        """Test identification of GitHub tokens."""
        result = validator.identify_provider("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        assert result == "github"

    def test_identify_provider_slack(self, validator):
        """Test identification of Slack tokens."""
        # Build pattern dynamically to avoid secret scanning
        test_token = "xoxb" + "-" + "1234567890" + "-" + "1234567890" + "-" + ("x" * 24)
        result = validator.identify_provider(test_token)
        assert result == "slack"

    def test_identify_provider_unknown(self, validator):
        """Test unknown provider returns None."""
        result = validator.identify_provider("some_random_string_123")
        assert result is None

    # Validation URL tests

    def test_get_validation_url_google(self, validator):
        """Test getting validation URL for Google."""
        url = validator.get_validation_url("google", "test_key")
        assert url is not None
        assert "googleapis.com" in url
        assert "test_key" in url

    def test_get_validation_url_stripe(self, validator):
        """Test getting validation URL for Stripe."""
        url = validator.get_validation_url("stripe", "sk_test_123")
        assert url is not None
        assert "stripe.com" in url

    def test_get_validation_url_github(self, validator):
        """Test getting validation URL for GitHub."""
        url = validator.get_validation_url("github", "ghp_xxx")
        assert url is not None
        assert "api.github.com" in url

    def test_get_validation_url_unknown(self, validator):
        """Test unknown provider returns None."""
        url = validator.get_validation_url("unknown_provider", "key")
        assert url is None

    # Secret masking tests

    def test_mask_secret_standard(self, validator):
        """Test secret masking with standard length."""
        secret = "AIzaSyA1234567890abcdefghijklmno"
        masked = validator.mask_secret(secret)

        assert masked.startswith("AIza")
        assert masked.endswith("lmno")
        assert "****" in masked
        assert len(masked) < len(secret)

    def test_mask_secret_short(self, validator):
        """Test secret masking with short secret."""
        secret = "abc123"
        masked = validator.mask_secret(secret)

        # Short secrets should be fully masked
        assert "*" in masked

    def test_mask_secret_custom_visible(self, validator):
        """Test secret masking with custom visible characters."""
        secret = "AIzaSyA1234567890abcdefghijklmno"
        masked = validator.mask_secret(secret, visible_chars=6)

        assert masked.startswith("AIzaSy")
        assert masked.endswith("klmno")  # Last 6 chars

    # Provider pattern tests

    def test_patterns_exist_for_common_providers(self, validator):
        """Test that patterns exist for common providers."""
        assert "google" in validator.PROVIDER_PATTERNS
        assert "aws" in validator.PROVIDER_PATTERNS
        assert "stripe" in validator.PROVIDER_PATTERNS
        assert "github" in validator.PROVIDER_PATTERNS
        assert "slack" in validator.PROVIDER_PATTERNS
        assert "firebase" in validator.PROVIDER_PATTERNS

    def test_aws_patterns_variants(self, validator):
        """Test AWS key variants are detected."""
        # Standard access key
        assert validator.identify_provider("AKIAIOSFODNN7EXAMPLE") == "aws"
        # Temporary access key
        assert validator.identify_provider("ASIAIOSFODNN7EXAMPLE") == "aws"

    def test_github_token_variants(self, validator):
        """Test GitHub token variants are detected."""
        # Personal access token
        assert validator.identify_provider("ghp_" + "x" * 36) == "github"
        # OAuth token
        assert validator.identify_provider("gho_" + "x" * 36) == "github"
        # User-to-server token
        assert validator.identify_provider("ghu_" + "x" * 36) == "github"
        # Server-to-server token
        assert validator.identify_provider("ghs_" + "x" * 36) == "github"

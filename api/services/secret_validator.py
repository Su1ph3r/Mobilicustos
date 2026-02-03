"""Secret validator service for checking if secrets are active."""

import logging
import re
from typing import Any

import httpx

from api.models.database import Secret

logger = logging.getLogger(__name__)


class SecretValidator:
    """Validates if detected secrets are still active/valid."""

    # Provider patterns for identification
    PROVIDER_PATTERNS = {
        "google": [
            r"AIza[0-9A-Za-z\-_]{20,}",  # Google API Key (typically 39 chars total)
        ],
        "aws": [
            r"AKIA[0-9A-Z]{16}",  # AWS Access Key ID
            r"ASIA[0-9A-Z]{16}",  # AWS Temporary Access Key
        ],
        "stripe": [
            r"sk_live_[0-9a-zA-Z]{24,}",  # Stripe Secret Key (live)
            r"sk_test_[0-9a-zA-Z]{24,}",  # Stripe Secret Key (test)
            r"pk_live_[0-9a-zA-Z]{24,}",  # Stripe Publishable Key (live)
            r"pk_test_[0-9a-zA-Z]{24,}",  # Stripe Publishable Key (test)
        ],
        "github": [
            r"ghp_[0-9a-zA-Z]{36}",  # GitHub Personal Access Token
            r"gho_[0-9a-zA-Z]{36}",  # GitHub OAuth Access Token
            r"ghu_[0-9a-zA-Z]{36}",  # GitHub User-to-Server Token
            r"ghs_[0-9a-zA-Z]{36}",  # GitHub Server-to-Server Token
        ],
        "slack": [
            r"xox[baprs]-[0-9A-Za-z\-]+",  # Slack tokens
        ],
        "firebase": [
            r"[a-z0-9-]+\.firebaseio\.com",  # Firebase URL
        ],
        "sendgrid": [
            r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",  # SendGrid API Key
        ],
        "twilio": [
            r"SK[0-9a-fA-F]{32}",  # Twilio API Key
        ],
    }

    def identify_provider(self, secret_value: str) -> str | None:
        """Identify the provider based on secret pattern."""
        for provider, patterns in self.PROVIDER_PATTERNS.items():
            for pattern in patterns:
                if re.match(pattern, secret_value):
                    return provider
        return None

    def get_validation_url(self, provider: str, api_key: str) -> str | None:
        """Get the validation URL for a provider."""
        validation_urls = {
            "google": f"https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={api_key}",
            "stripe": "https://api.stripe.com/v1/balance",
            "github": "https://api.github.com/user",
            "slack": "https://slack.com/api/auth.test",
            "sendgrid": "https://api.sendgrid.com/v3/user/profile",
        }
        return validation_urls.get(provider)

    def mask_secret(self, secret_value: str, visible_chars: int = 4) -> str:
        """Mask a secret value for safe display."""
        if len(secret_value) <= visible_chars * 2:
            return "*" * len(secret_value)

        prefix = secret_value[:visible_chars]
        suffix = secret_value[-visible_chars:]
        mask_length = len(secret_value) - (visible_chars * 2)
        return f"{prefix}{'*' * min(mask_length, 8)}{suffix}"

    async def validate(self, secret: Secret) -> tuple[bool, str | None]:
        """Validate a secret and return (is_valid, error_message)."""
        try:
            if secret.provider == "aws":
                return await self._validate_aws(secret)
            elif secret.provider == "google":
                return await self._validate_google(secret)
            elif secret.provider == "firebase":
                return await self._validate_firebase(secret)
            elif secret.provider == "stripe":
                return await self._validate_stripe(secret)
            elif secret.provider == "github":
                return await self._validate_github(secret)
            elif secret.provider == "slack":
                return await self._validate_slack(secret)
            else:
                return None, "Validation not implemented for this provider"
        except Exception as e:
            logger.error(f"Secret validation failed: {e}")
            return None, str(e)

    async def _validate_aws(self, secret: Secret) -> tuple[bool, str | None]:
        """Validate AWS credentials."""
        # Note: Actually testing AWS credentials would require the secret key
        # This is a placeholder that would need the full credential pair
        logger.info("AWS validation would require additional secret key")
        return None, "AWS validation requires both access key and secret key"

    async def _validate_google(self, secret: Secret) -> tuple[bool, str | None]:
        """Validate Google API key."""
        # Test by making a simple API call that requires an API key
        # Using a safe, read-only API endpoint
        try:
            async with httpx.AsyncClient() as client:
                # Use a minimal API that just validates the key format
                # Don't actually make requests to Google services
                api_key = self._extract_key_from_context(secret)
                if api_key and api_key.startswith("AIza"):
                    return None, "Key format appears valid, manual testing required"
                return False, "Invalid key format"
        except Exception as e:
            return None, str(e)

    async def _validate_firebase(self, secret: Secret) -> tuple[bool, str | None]:
        """Validate Firebase credentials."""
        # Check if Firebase URL is accessible
        try:
            context = secret.context or ""
            url_match = re.search(r'https://[a-z0-9-]+\.firebaseio\.com', context)

            if url_match:
                url = url_match.group(0)
                async with httpx.AsyncClient() as client:
                    response = await client.get(f"{url}/.json", timeout=5)
                    if response.status_code == 200:
                        return True, None
                    elif response.status_code == 401:
                        return None, "Database requires authentication"
                    else:
                        return False, f"HTTP {response.status_code}"

            return None, "Could not extract Firebase URL"
        except Exception as e:
            return None, str(e)

    async def _validate_stripe(self, secret: Secret) -> tuple[bool, str | None]:
        """Validate Stripe API key."""
        try:
            api_key = self._extract_key_from_context(secret)
            if not api_key:
                return None, "Could not extract key"

            # Check key prefix
            if api_key.startswith("sk_live_"):
                # Live secret key - DON'T actually test this
                return None, "Live secret key detected - manual verification required"
            elif api_key.startswith("pk_live_"):
                return None, "Publishable key - limited risk"
            elif api_key.startswith("sk_test_"):
                return None, "Test secret key - lower risk"

            return None, "Unknown key type"
        except Exception as e:
            return None, str(e)

    async def _validate_github(self, secret: Secret) -> tuple[bool, str | None]:
        """Validate GitHub token."""
        try:
            api_key = self._extract_key_from_context(secret)
            if not api_key:
                return None, "Could not extract token"

            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "https://api.github.com/user",
                    headers={"Authorization": f"token {api_key}"},
                    timeout=5,
                )

                if response.status_code == 200:
                    user_data = response.json()
                    return True, f"Valid token for user: {user_data.get('login')}"
                elif response.status_code == 401:
                    return False, "Token is invalid or expired"
                else:
                    return None, f"HTTP {response.status_code}"

        except Exception as e:
            return None, str(e)

    async def _validate_slack(self, secret: Secret) -> tuple[bool, str | None]:
        """Validate Slack token or webhook."""
        try:
            context = secret.context or ""

            # Check for webhook URL
            webhook_match = re.search(
                r'https://hooks\.slack\.com/services/[A-Za-z0-9/]+',
                context,
            )
            if webhook_match:
                return None, "Webhook URL detected - test by sending message"

            # Check for token
            token_match = re.search(r'xox[baprs]-[0-9A-Za-z-]+', context)
            if token_match:
                token = token_match.group(0)

                async with httpx.AsyncClient() as client:
                    response = await client.post(
                        "https://slack.com/api/auth.test",
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=5,
                    )

                    data = response.json()
                    if data.get("ok"):
                        return True, f"Valid token for: {data.get('team')}"
                    else:
                        return False, data.get("error", "Unknown error")

            return None, "Could not extract token or webhook"

        except Exception as e:
            return None, str(e)

    def _extract_key_from_context(self, secret: Secret) -> str | None:
        """Extract the actual secret value from context."""
        # The secret value is partially redacted, so we need to look at context
        # In a real implementation, we might have access to the full value
        # For now, return the redacted value
        return secret.secret_value_redacted

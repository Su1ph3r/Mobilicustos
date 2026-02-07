"""Tests for CryptoAuditor analyzer."""

import pytest
from api.tests.conftest import create_test_archive, make_mock_app


WEAK_CRYPTO_JAVA = """
import javax.crypto.Cipher;
import java.security.MessageDigest;

public class CryptoUtils {
    public void weakEncryption() throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        MessageDigest md = MessageDigest.getInstance("MD5");
    }

    public int getToken() {
        java.util.Random random = new java.util.Random();
        return random.nextInt();
    }

    private static final String SECRET_KEY = "0123456789abcdef0123456789abcdef";

    public void staticIv() {
        byte[] iv = new byte[16];
        javax.crypto.spec.IvParameterSpec ivSpec =
            new javax.crypto.spec.IvParameterSpec(iv);
    }
}
"""

SECURE_CRYPTO_JAVA = """
import javax.crypto.Cipher;
import java.security.SecureRandom;

public class SecureCrypto {
    public void encrypt() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[12];
        random.nextBytes(iv);
    }
}
"""


class TestCryptoAuditor:
    @pytest.fixture
    def analyzer(self):
        from api.services.analyzers.crypto_auditor import CryptoAuditor
        return CryptoAuditor()

    @pytest.fixture
    def weak_crypto_app(self, tmp_path):
        return make_mock_app(tmp_path, {
            "sources/com/example/CryptoUtils.java": WEAK_CRYPTO_JAVA,
        })

    @pytest.fixture
    def secure_crypto_app(self, tmp_path):
        return make_mock_app(tmp_path, {
            "sources/com/example/SecureCrypto.java": SECURE_CRYPTO_JAVA,
        })

    @pytest.mark.asyncio
    async def test_detects_weak_algorithms(self, analyzer, weak_crypto_app):
        findings = await analyzer.analyze(weak_crypto_app)
        assert isinstance(findings, list)
        assert len(findings) > 0
        titles = " ".join(f.title.lower() for f in findings)
        assert "des" in titles or "md5" in titles or "weak" in titles or "ecb" in titles

    @pytest.mark.asyncio
    async def test_detects_insecure_random(self, analyzer, weak_crypto_app):
        findings = await analyzer.analyze(weak_crypto_app)
        texts = " ".join((f.title + " " + f.description).lower() for f in findings)
        assert "random" in texts or "prng" in texts or "insecure" in texts

    @pytest.mark.asyncio
    async def test_secure_crypto_fewer_findings(self, analyzer, secure_crypto_app):
        findings = await analyzer.analyze(secure_crypto_app)
        critical = [f for f in findings if f.severity in ("critical", "high")]
        assert len(critical) == 0

    @pytest.mark.asyncio
    async def test_findings_have_required_fields(self, analyzer, weak_crypto_app):
        findings = await analyzer.analyze(weak_crypto_app)
        for f in findings:
            assert f.finding_id
            assert f.title
            assert f.description
            assert f.severity in ("critical", "high", "medium", "low", "info")
            assert f.tool == "crypto_auditor"

    @pytest.mark.asyncio
    async def test_no_archive_returns_empty(self, analyzer, tmp_path):
        app = make_mock_app(tmp_path, files=None)
        findings = await analyzer.analyze(app)
        assert findings == []

    @pytest.mark.asyncio
    async def test_no_source_files_returns_empty(self, analyzer, tmp_path):
        app = make_mock_app(tmp_path, {"dummy.txt": "no crypto here"})
        findings = await analyzer.analyze(app)
        assert findings == []

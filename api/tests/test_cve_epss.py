"""Tests for EPSS client."""

import pytest
from decimal import Decimal
from unittest.mock import patch, AsyncMock, MagicMock
from api.services.cve.sources.epss_client import EPSSClient, EPSSScore


class TestEPSSClient:
    @pytest.fixture
    def client(self):
        return EPSSClient(timeout=5)

    @pytest.mark.asyncio
    @patch("httpx.AsyncClient.get", new_callable=AsyncMock)
    async def test_get_scores_single(self, mock_get, client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": [
                {"cve": "CVE-2023-1234", "epss": "0.97", "percentile": "0.99"},
            ]
        }
        mock_get.return_value = mock_response

        results = await client.get_scores(["CVE-2023-1234"])
        assert "CVE-2023-1234" in results
        assert results["CVE-2023-1234"].epss_score == Decimal("0.97")
        assert results["CVE-2023-1234"].percentile == Decimal("0.99")

    @pytest.mark.asyncio
    @patch("httpx.AsyncClient.get", new_callable=AsyncMock)
    async def test_get_scores_multiple(self, mock_get, client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": [
                {"cve": "CVE-2023-1234", "epss": "0.97", "percentile": "0.99"},
                {"cve": "CVE-2023-5678", "epss": "0.02", "percentile": "0.45"},
            ]
        }
        mock_get.return_value = mock_response

        results = await client.get_scores(["CVE-2023-1234", "CVE-2023-5678"])
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_get_scores_empty_list(self, client):
        results = await client.get_scores([])
        assert results == {}

    @pytest.mark.asyncio
    @patch("httpx.AsyncClient.get", new_callable=AsyncMock)
    async def test_get_single_score(self, mock_get, client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": [
                {"cve": "CVE-2023-1234", "epss": "0.50", "percentile": "0.75"},
            ]
        }
        mock_get.return_value = mock_response

        score = await client.get_score("CVE-2023-1234")
        assert score is not None
        assert score.cve_id == "CVE-2023-1234"
        assert score.epss_score == Decimal("0.50")

    @pytest.mark.asyncio
    @patch("httpx.AsyncClient.get", new_callable=AsyncMock)
    async def test_handles_timeout(self, mock_get, client):
        import httpx
        mock_get.side_effect = httpx.TimeoutException("timeout")
        results = await client.get_scores(["CVE-2023-1234"])
        assert results == {}

    @pytest.mark.asyncio
    @patch("httpx.AsyncClient.get", new_callable=AsyncMock)
    async def test_handles_http_error(self, mock_get, client):
        import httpx
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_get.side_effect = httpx.HTTPStatusError(
            "Server Error", request=MagicMock(), response=mock_response
        )
        results = await client.get_scores(["CVE-2023-1234"])
        assert results == {}

    @pytest.mark.asyncio
    @patch("httpx.AsyncClient.get", new_callable=AsyncMock)
    async def test_batching_over_100(self, mock_get, client):
        """Should batch CVE IDs into chunks of 100."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"data": []}
        mock_get.return_value = mock_response

        cve_ids = [f"CVE-2023-{i:04d}" for i in range(150)]
        await client.get_scores(cve_ids)
        # Should have made 2 API calls (100 + 50)
        assert mock_get.call_count == 2

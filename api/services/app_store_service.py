"""
App Store Connector Service

Connects to app stores for automated app retrieval:
- Google Play Store
- Apple App Store
- APKPure
- APKMirror

Supports:
- App metadata retrieval
- APK/IPA download
- Version monitoring
"""

import asyncio
import hashlib
import logging
import os
import re
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional
from uuid import uuid4

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class AppStoreClient(ABC):
    """Abstract base class for app store clients."""

    @abstractmethod
    async def search(self, query: str, limit: int = 10) -> list[dict]:
        """Search for apps."""
        pass

    @abstractmethod
    async def get_app_info(self, app_id: str) -> Optional[dict]:
        """Get app metadata."""
        pass

    @abstractmethod
    async def download(self, app_id: str, output_path: str) -> Optional[str]:
        """Download app binary."""
        pass


class GooglePlayClient(AppStoreClient):
    """Google Play Store client using various methods."""

    def __init__(self, email: Optional[str] = None, password: Optional[str] = None):
        self.email = email
        self.password = password
        self.http = httpx.AsyncClient(timeout=60.0)

    async def search(self, query: str, limit: int = 10) -> list[dict]:
        """Search Google Play using web scraping."""
        # Note: In production, use google-play-scraper or similar
        # This is a simplified implementation
        try:
            response = await self.http.get(
                f"https://play.google.com/store/search",
                params={"q": query, "c": "apps"},
                headers={"User-Agent": "Mozilla/5.0"},
            )

            if response.status_code != 200:
                return []

            # Parse results (simplified - would use proper parsing)
            apps = []
            # Pattern to extract app IDs from search results
            pattern = r'/store/apps/details\?id=([a-zA-Z0-9._]+)'
            matches = re.findall(pattern, response.text)

            for app_id in matches[:limit]:
                info = await self.get_app_info(app_id)
                if info:
                    apps.append(info)

            return apps
        except Exception as e:
            logger.error(f"Search failed: {e}")
            return []

    async def get_app_info(self, app_id: str) -> Optional[dict]:
        """Get app info from Google Play."""
        try:
            response = await self.http.get(
                f"https://play.google.com/store/apps/details",
                params={"id": app_id},
                headers={"User-Agent": "Mozilla/5.0"},
            )

            if response.status_code != 200:
                return None

            # Parse page (simplified)
            html = response.text

            # Extract title
            title_match = re.search(r'<h1[^>]*>([^<]+)</h1>', html)
            title = title_match.group(1) if title_match else app_id

            # Extract version (simplified)
            version_match = re.search(r'Current Version.*?(\d+\.\d+[.\d]*)', html, re.DOTALL)
            version = version_match.group(1) if version_match else "Unknown"

            return {
                "store": "google_play",
                "app_id": app_id,
                "package_name": app_id,
                "title": title,
                "version": version,
                "url": f"https://play.google.com/store/apps/details?id={app_id}",
            }
        except Exception as e:
            logger.error(f"Get app info failed: {e}")
            return None

    async def download(self, app_id: str, output_path: str) -> Optional[str]:
        """Download APK (requires authenticated session or alternative source)."""
        # Note: Direct download from Play Store requires authentication
        # In production, use googleplay-api or download from APKPure/APKMirror
        logger.warning("Direct Play Store download not implemented - use APKPure")
        return None


class AppStoreIOSClient(AppStoreClient):
    """Apple App Store client."""

    def __init__(self, apple_id: Optional[str] = None, password: Optional[str] = None):
        self.apple_id = apple_id
        self.password = password
        self.http = httpx.AsyncClient(timeout=60.0)

    async def search(self, query: str, limit: int = 10) -> list[dict]:
        """Search App Store using iTunes API."""
        try:
            response = await self.http.get(
                "https://itunes.apple.com/search",
                params={
                    "term": query,
                    "entity": "software",
                    "limit": limit,
                },
            )

            if response.status_code != 200:
                return []

            data = response.json()
            apps = []

            for result in data.get("results", []):
                apps.append({
                    "store": "app_store",
                    "app_id": str(result.get("trackId")),
                    "bundle_id": result.get("bundleId"),
                    "title": result.get("trackName"),
                    "version": result.get("version"),
                    "developer": result.get("artistName"),
                    "url": result.get("trackViewUrl"),
                    "icon_url": result.get("artworkUrl100"),
                    "rating": result.get("averageUserRating"),
                    "size_bytes": result.get("fileSizeBytes"),
                })

            return apps
        except Exception as e:
            logger.error(f"Search failed: {e}")
            return []

    async def get_app_info(self, app_id: str) -> Optional[dict]:
        """Get app info from App Store."""
        try:
            response = await self.http.get(
                "https://itunes.apple.com/lookup",
                params={"id": app_id},
            )

            if response.status_code != 200:
                return None

            data = response.json()
            results = data.get("results", [])

            if not results:
                return None

            result = results[0]
            return {
                "store": "app_store",
                "app_id": str(result.get("trackId")),
                "bundle_id": result.get("bundleId"),
                "title": result.get("trackName"),
                "version": result.get("version"),
                "developer": result.get("artistName"),
                "url": result.get("trackViewUrl"),
                "icon_url": result.get("artworkUrl100"),
                "description": result.get("description", "")[:500],
                "rating": result.get("averageUserRating"),
                "size_bytes": result.get("fileSizeBytes"),
                "minimum_os": result.get("minimumOsVersion"),
            }
        except Exception as e:
            logger.error(f"Get app info failed: {e}")
            return None

    async def download(self, app_id: str, output_path: str) -> Optional[str]:
        """Download IPA (requires Apple ID with purchased app)."""
        # Note: IPA download requires ipatool or similar with Apple ID
        logger.warning("Direct App Store download not implemented - use ipatool")
        return None


class APKPureClient(AppStoreClient):
    """APKPure client for APK downloads."""

    def __init__(self):
        self.http = httpx.AsyncClient(
            timeout=120.0,
            headers={"User-Agent": "Mozilla/5.0"},
            follow_redirects=True,
        )

    async def search(self, query: str, limit: int = 10) -> list[dict]:
        """Search APKPure."""
        try:
            response = await self.http.get(
                f"https://apkpure.com/search",
                params={"q": query},
            )

            if response.status_code != 200:
                return []

            # Parse results (simplified)
            apps = []
            pattern = r'href="/([a-z0-9-]+)/([a-zA-Z0-9._]+)"'
            matches = re.findall(pattern, response.text)

            seen = set()
            for slug, package in matches[:limit * 2]:
                if package not in seen and '.' in package:
                    seen.add(package)
                    apps.append({
                        "store": "apkpure",
                        "app_id": package,
                        "package_name": package,
                        "slug": slug,
                        "url": f"https://apkpure.com/{slug}/{package}",
                    })

                if len(apps) >= limit:
                    break

            return apps
        except Exception as e:
            logger.error(f"Search failed: {e}")
            return []

    async def get_app_info(self, app_id: str) -> Optional[dict]:
        """Get app info from APKPure."""
        try:
            # Search for the app first to get the slug
            results = await self.search(app_id, limit=1)
            if not results:
                return None

            app = results[0]

            # Get detailed page
            response = await self.http.get(app["url"])
            if response.status_code != 200:
                return None

            # Parse version
            version_match = re.search(r'<span class="info-item">(\d+\.\d+[.\d]*)</span>', response.text)
            version = version_match.group(1) if version_match else "Unknown"

            app["version"] = version
            return app
        except Exception as e:
            logger.error(f"Get app info failed: {e}")
            return None

    async def download(self, app_id: str, output_path: str) -> Optional[str]:
        """Download APK from APKPure."""
        try:
            # Get app info first
            info = await self.get_app_info(app_id)
            if not info:
                return None

            # Get download page
            download_url = f"{info['url']}/download"
            response = await self.http.get(download_url)

            if response.status_code != 200:
                return None

            # Find download link
            link_match = re.search(r'href="(https://[^"]+\.apk[^"]*)"', response.text)
            if not link_match:
                return None

            apk_url = link_match.group(1)

            # Download APK
            async with self.http.stream("GET", apk_url) as download_response:
                if download_response.status_code != 200:
                    return None

                filename = f"{app_id}_{datetime.utcnow().strftime('%Y%m%d')}.apk"
                filepath = os.path.join(output_path, filename)

                with open(filepath, "wb") as f:
                    async for chunk in download_response.aiter_bytes(8192):
                        f.write(chunk)

                return filepath
        except Exception as e:
            logger.error(f"Download failed: {e}")
            return None


class AppStoreService:
    """Service for app store integrations."""

    STORE_TYPES = ["google_play", "app_store", "apkpure", "apkmirror"]

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_connection(
        self,
        name: str,
        store_type: str,
        credentials: Optional[dict] = None,
        is_active: bool = True,
    ) -> dict:
        """Create an app store connection."""
        connection_id = str(uuid4())

        if store_type not in self.STORE_TYPES:
            raise ValueError(f"Unsupported store type: {store_type}")

        import json

        query = """
            INSERT INTO app_store_connections (
                connection_id, name, store_type, credentials,
                is_active, created_at
            ) VALUES (
                :connection_id, :name, :store_type, :credentials,
                :is_active, :created_at
            )
            RETURNING *
        """

        await self.db.execute(query, {
            "connection_id": connection_id,
            "name": name,
            "store_type": store_type,
            "credentials": json.dumps(credentials) if credentials else None,
            "is_active": is_active,
            "created_at": datetime.utcnow(),
        })
        await self.db.commit()

        return {
            "connection_id": connection_id,
            "name": name,
            "store_type": store_type,
            "is_active": is_active,
        }

    async def list_connections(self) -> list[dict]:
        """List all app store connections."""
        query = """
            SELECT connection_id, name, store_type, is_active, created_at
            FROM app_store_connections
            ORDER BY created_at DESC
        """
        result = await self.db.execute(query)
        return [dict(row._mapping) for row in result.fetchall()]

    async def delete_connection(self, connection_id: str) -> bool:
        """Delete an app store connection."""
        query = "DELETE FROM app_store_connections WHERE connection_id = :connection_id"
        result = await self.db.execute(query, {"connection_id": connection_id})
        await self.db.commit()
        return result.rowcount > 0

    async def search_apps(
        self,
        store_type: str,
        query: str,
        limit: int = 10,
    ) -> list[dict]:
        """Search for apps in a store."""
        client = self._get_client(store_type)
        return await client.search(query, limit)

    async def get_app_info(
        self,
        store_type: str,
        app_id: str,
    ) -> Optional[dict]:
        """Get app information from a store."""
        client = self._get_client(store_type)
        return await client.get_app_info(app_id)

    async def download_app(
        self,
        store_type: str,
        app_id: str,
        output_path: str,
    ) -> Optional[str]:
        """Download an app from a store."""
        client = self._get_client(store_type)
        return await client.download(app_id, output_path)

    async def import_app(
        self,
        store_type: str,
        app_id: str,
        download_path: str,
    ) -> Optional[dict]:
        """Download and import an app into Mobilicustos."""
        # Get app info
        info = await self.get_app_info(store_type, app_id)
        if not info:
            raise ValueError("App not found in store")

        # Download app
        filepath = await self.download_app(store_type, app_id, download_path)
        if not filepath:
            raise ValueError("Download failed")

        # Calculate hash
        with open(filepath, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        # Check if already exists
        existing = await self.db.execute(
            "SELECT app_id FROM mobile_apps WHERE file_hash = :hash",
            {"hash": file_hash}
        )
        if existing.fetchone():
            os.remove(filepath)
            raise ValueError("App already exists in database")

        # Create app record
        new_app_id = str(uuid4())
        platform = "ios" if store_type == "app_store" else "android"

        query = """
            INSERT INTO mobile_apps (
                app_id, app_name, package_name, version, platform,
                file_path, file_hash, store_source, store_app_id, created_at
            ) VALUES (
                :app_id, :app_name, :package_name, :version, :platform,
                :file_path, :file_hash, :store_source, :store_app_id, :created_at
            )
            RETURNING *
        """

        result = await self.db.execute(query, {
            "app_id": new_app_id,
            "app_name": info.get("title", app_id),
            "package_name": info.get("bundle_id") or info.get("package_name", app_id),
            "version": info.get("version"),
            "platform": platform,
            "file_path": filepath,
            "file_hash": file_hash,
            "store_source": store_type,
            "store_app_id": app_id,
            "created_at": datetime.utcnow(),
        })
        await self.db.commit()

        row = result.fetchone()
        return dict(row._mapping) if row else None

    def _get_client(self, store_type: str, credentials: Optional[dict] = None) -> AppStoreClient:
        """Get appropriate store client."""
        if store_type == "google_play":
            return GooglePlayClient()
        elif store_type == "app_store":
            return AppStoreIOSClient()
        elif store_type == "apkpure":
            return APKPureClient()
        else:
            raise ValueError(f"Unsupported store type: {store_type}")

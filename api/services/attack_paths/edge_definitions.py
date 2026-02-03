"""Edge definitions for mobile attack path analysis.

This module defines the edges (transitions) that can occur between findings
in an attack graph. Each edge represents how one vulnerability enables
another attack or capability.
"""

from typing import Any

# Entry point types - where attacks can begin
ENTRY_POINT_TYPES = {
    "exported_activity": {
        "name": "Exported Activity",
        "description": "Activity accessible to other apps without permission",
        "requires_physical": False,
    },
    "exported_service": {
        "name": "Exported Service",
        "description": "Service accessible to other apps without permission",
        "requires_physical": False,
    },
    "exported_provider": {
        "name": "Exported Content Provider",
        "description": "Content provider accessible without permission",
        "requires_physical": False,
    },
    "exported_receiver": {
        "name": "Exported Broadcast Receiver",
        "description": "Receiver accessible to broadcast intents",
        "requires_physical": False,
    },
    "deep_link": {
        "name": "Deep Link Handler",
        "description": "Custom URL scheme or universal link handler",
        "requires_physical": False,
    },
    "webview_js": {
        "name": "JavaScript-enabled WebView",
        "description": "WebView with JavaScript enabled loading untrusted content",
        "requires_physical": False,
    },
    "debuggable_app": {
        "name": "Debuggable Application",
        "description": "Application with debug flag enabled",
        "requires_physical": True,
    },
    "hardcoded_credential": {
        "name": "Hardcoded Credentials",
        "description": "Credentials embedded in application code",
        "requires_physical": False,
    },
    "cleartext_network": {
        "name": "Cleartext Network Traffic",
        "description": "HTTP traffic allowing interception",
        "requires_physical": False,
    },
    "backup_enabled": {
        "name": "Backup Enabled",
        "description": "Application data can be extracted via backup",
        "requires_physical": True,
    },
    "ssl_bypass": {
        "name": "SSL Validation Bypass",
        "description": "Certificate validation disabled",
        "requires_physical": False,
    },
}

# Target types - end goals of attack paths
TARGET_TYPES = {
    "data_theft": {
        "name": "Access to sensitive user data",
        "impact_c": 90, "impact_i": 10, "impact_a": 0,
    },
    "credential_theft": {
        "name": "Steal authentication credentials",
        "impact_c": 100, "impact_i": 20, "impact_a": 0,
    },
    "session_hijacking": {
        "name": "Hijack user session",
        "impact_c": 80, "impact_i": 60, "impact_a": 0,
    },
    "code_execution": {
        "name": "Execute arbitrary code",
        "impact_c": 70, "impact_i": 100, "impact_a": 50,
    },
    "privilege_escalation": {
        "name": "Escalate privileges",
        "impact_c": 60, "impact_i": 80, "impact_a": 30,
    },
    "backend_compromise": {
        "name": "Compromise backend services",
        "impact_c": 100, "impact_i": 100, "impact_a": 70,
    },
    "financial_fraud": {
        "name": "Financial fraud or theft",
        "impact_c": 70, "impact_i": 90, "impact_a": 40,
    },
    "data_manipulation": {
        "name": "Modify application data",
        "impact_c": 30, "impact_i": 90, "impact_a": 20,
    },
}

# Edge definitions - how findings connect to form attack paths
EDGE_DEFINITIONS: dict[str, dict[str, Any]] = {
    # === Component Security Edges ===
    "exported_activity_to_data_access": {
        "name": "Exported Activity Data Access",
        "check_patterns": [r"exported.*activity", r"activity.*exported"],
        "category_patterns": ["Component Security"],
        "severity_patterns": ["high", "medium"],
        "entry_point_type": "exported_activity",
        "target_types": ["data_theft", "privilege_escalation"],
        "mitre_mobile": ["T1405"],
        "exploitability": "easy",
        "confidence": 0.8,
        "requires_physical": False,
        "skill_level": "novice",
        "poc_template": "adb shell am start -n {package_name}/{component_name}",
        "enables": ["data_access", "function_invocation"],
        "description": "Exported activity allows direct invocation to access data or trigger actions",
    },
    "exported_service_to_privileged_ops": {
        "name": "Exported Service Exploitation",
        "check_patterns": [r"exported.*service", r"service.*exported"],
        "category_patterns": ["Component Security"],
        "severity_patterns": ["high", "critical"],
        "entry_point_type": "exported_service",
        "target_types": ["privilege_escalation", "code_execution"],
        "mitre_mobile": ["T1405"],
        "exploitability": "moderate",
        "confidence": 0.7,
        "requires_physical": False,
        "skill_level": "intermediate",
        "poc_template": "adb shell am startservice -n {package_name}/{component_name}",
        "enables": ["service_access", "privileged_operations"],
        "description": "Exported service allows binding to execute privileged operations",
    },
    "exported_provider_to_data_theft": {
        "name": "Content Provider Data Theft",
        "check_patterns": [r"exported.*provider", r"provider.*exported", r"content provider"],
        "category_patterns": ["Component Security"],
        "severity_patterns": ["high", "critical"],
        "entry_point_type": "exported_provider",
        "target_types": ["data_theft", "data_manipulation"],
        "mitre_mobile": ["T1405", "T1409"],
        "exploitability": "easy",
        "confidence": 0.9,
        "requires_physical": False,
        "skill_level": "novice",
        "poc_template": "adb shell content query --uri content://{package_name}.provider/",
        "enables": ["data_read", "data_write", "sql_injection"],
        "description": "Exported content provider allows direct database queries",
    },

    # === Network Security Edges ===
    "cleartext_to_credential_theft": {
        "name": "Cleartext Traffic Credential Interception",
        "check_patterns": [r"cleartext", r"http traffic", r"usesCleartextTraffic"],
        "category_patterns": ["Network Security"],
        "severity_patterns": ["high", "critical"],
        "entry_point_type": "cleartext_network",
        "target_types": ["credential_theft", "session_hijacking", "data_theft"],
        "mitre_mobile": ["T1439"],
        "exploitability": "easy",
        "confidence": 0.95,
        "requires_physical": False,
        "requires_network": True,
        "skill_level": "novice",
        "poc_template": "mitmproxy -p 8080",
        "enables": ["network_interception", "traffic_modification"],
        "description": "HTTP traffic can be intercepted to steal credentials",
    },
    "ssl_bypass_to_mitm": {
        "name": "SSL Bypass to MITM",
        "check_patterns": [r"ssl.*bypass", r"certificate.*validation", r"trustmanager", r"hostname.*verifier"],
        "category_patterns": ["Network Security"],
        "severity_patterns": ["critical"],
        "entry_point_type": "ssl_bypass",
        "target_types": ["credential_theft", "session_hijacking", "data_theft"],
        "mitre_mobile": ["T1439"],
        "exploitability": "easy",
        "confidence": 0.95,
        "requires_physical": False,
        "requires_network": True,
        "skill_level": "novice",
        "poc_template": "mitmproxy --ssl-insecure -p 8080",
        "enables": ["network_interception", "traffic_modification"],
        "description": "Disabled SSL validation allows trivial MITM attacks",
    },
    "no_pinning_to_mitm": {
        "name": "Missing Pinning to MITM",
        "check_patterns": [r"pinning not detected", r"no.*pinning", r"certificate pinning"],
        "category_patterns": ["Network Security"],
        "severity_patterns": ["medium", "high"],
        "entry_point_type": "cleartext_network",
        "target_types": ["credential_theft", "session_hijacking"],
        "mitre_mobile": ["T1439"],
        "exploitability": "moderate",
        "confidence": 0.7,
        "requires_physical": False,
        "requires_network": True,
        "skill_level": "intermediate",
        "enables": ["network_interception"],
        "description": "Without pinning, compromised CA or user-installed cert enables MITM",
    },

    # === Cryptography Edges ===
    "weak_crypto_to_data_decryption": {
        "name": "Weak Cryptography Data Decryption",
        "check_patterns": [r"weak.*crypt", r"des\b", r"rc4", r"ecb", r"md5"],
        "category_patterns": ["Cryptography"],
        "severity_patterns": ["high", "critical"],
        "entry_point_type": None,
        "target_types": ["data_theft", "credential_theft"],
        "mitre_mobile": ["T1521"],
        "exploitability": "moderate",
        "confidence": 0.7,
        "requires_physical": False,
        "skill_level": "intermediate",
        "enables": ["data_decryption"],
        "description": "Weak cryptographic algorithms can be broken to expose data",
    },
    "hardcoded_key_to_decryption": {
        "name": "Hardcoded Key to Data Decryption",
        "check_patterns": [r"hardcoded.*key", r"embedded.*key", r"key.*hardcoded"],
        "category_patterns": ["Cryptography", "Secrets"],
        "severity_patterns": ["critical"],
        "entry_point_type": "hardcoded_credential",
        "target_types": ["data_theft", "credential_theft"],
        "mitre_mobile": ["T1517"],
        "exploitability": "easy",
        "confidence": 0.95,
        "requires_physical": False,
        "skill_level": "novice",
        "enables": ["data_decryption", "impersonation"],
        "description": "Extracted hardcoded key allows decryption of all protected data",
    },

    # === Storage Edges ===
    "backup_to_data_extraction": {
        "name": "Backup Data Extraction",
        "check_patterns": [r"backup.*enabled", r"allowbackup"],
        "category_patterns": ["Data Protection"],
        "severity_patterns": ["medium", "high"],
        "entry_point_type": "backup_enabled",
        "target_types": ["data_theft", "credential_theft"],
        "mitre_mobile": ["T1409"],
        "exploitability": "easy",
        "confidence": 0.9,
        "requires_physical": True,
        "skill_level": "novice",
        "poc_template": "adb backup -f backup.ab -apk {package_name}",
        "enables": ["data_extraction"],
        "description": "ADB backup allows extraction of all app data",
    },
    "world_readable_to_theft": {
        "name": "World Readable File Data Theft",
        "check_patterns": [r"world.*readable", r"mode_world"],
        "category_patterns": ["File Security", "Data Protection"],
        "severity_patterns": ["high"],
        "entry_point_type": None,
        "target_types": ["data_theft", "credential_theft"],
        "mitre_mobile": ["T1409"],
        "exploitability": "easy",
        "confidence": 0.9,
        "requires_physical": False,
        "skill_level": "novice",
        "enables": ["data_read"],
        "description": "World-readable files can be accessed by any app",
    },
    "insecure_storage_to_credential_theft": {
        "name": "Insecure Storage Credential Theft",
        "check_patterns": [r"sharedpreferences.*password", r"userdefaults.*password", r"cleartext.*storage"],
        "category_patterns": ["Data Protection", "Authentication"],
        "severity_patterns": ["high", "critical"],
        "entry_point_type": "backup_enabled",
        "target_types": ["credential_theft", "session_hijacking"],
        "mitre_mobile": ["T1409"],
        "exploitability": "easy",
        "confidence": 0.85,
        "requires_physical": True,
        "skill_level": "novice",
        "enables": ["credential_extraction"],
        "description": "Credentials stored insecurely can be extracted",
    },

    # === Debug/Configuration Edges ===
    "debuggable_to_full_access": {
        "name": "Debuggable App Full Access",
        "check_patterns": [r"debuggable", r"debug.*enabled"],
        "category_patterns": ["Configuration"],
        "severity_patterns": ["high", "critical"],
        "entry_point_type": "debuggable_app",
        "target_types": ["data_theft", "code_execution", "privilege_escalation"],
        "mitre_mobile": ["T1407"],
        "exploitability": "easy",
        "confidence": 0.95,
        "requires_physical": True,
        "skill_level": "intermediate",
        "poc_template": "adb shell run-as {package_name} ls /data/data/{package_name}",
        "enables": ["debug_access", "memory_inspection", "code_modification"],
        "description": "Debuggable flag allows attaching debugger and full app access",
    },

    # === WebView Edges ===
    "webview_js_to_xss": {
        "name": "WebView JavaScript XSS",
        "check_patterns": [r"javascript.*enabled", r"webview.*javascript"],
        "category_patterns": ["WebView"],
        "severity_patterns": ["medium", "high"],
        "entry_point_type": "webview_js",
        "target_types": ["data_theft", "session_hijacking"],
        "mitre_mobile": ["T1403"],
        "exploitability": "moderate",
        "confidence": 0.7,
        "requires_physical": False,
        "skill_level": "intermediate",
        "enables": ["xss", "data_access"],
        "description": "JavaScript in WebView can be exploited for XSS",
    },
    "webview_interface_to_code_execution": {
        "name": "JavaScript Interface Code Execution",
        "check_patterns": [r"addjavascriptinterface", r"javascript.*interface"],
        "category_patterns": ["WebView"],
        "severity_patterns": ["high", "critical"],
        "entry_point_type": "webview_js",
        "target_types": ["code_execution", "data_theft"],
        "mitre_mobile": ["T1403"],
        "exploitability": "moderate",
        "confidence": 0.8,
        "requires_physical": False,
        "skill_level": "intermediate",
        "enables": ["code_execution", "native_method_call"],
        "description": "Exposed JavaScript interface allows calling native methods",
    },
    "webview_file_access_to_data_theft": {
        "name": "WebView File Access Data Theft",
        "check_patterns": [r"file.*access.*webview", r"allowfileaccess"],
        "category_patterns": ["WebView"],
        "severity_patterns": ["medium", "high"],
        "entry_point_type": "webview_js",
        "target_types": ["data_theft"],
        "mitre_mobile": ["T1409"],
        "exploitability": "moderate",
        "confidence": 0.75,
        "requires_physical": False,
        "skill_level": "intermediate",
        "enables": ["local_file_read"],
        "description": "WebView file access allows reading local files",
    },

    # === Secrets Edges ===
    "exposed_api_key_to_backend": {
        "name": "Exposed API Key Backend Access",
        "check_patterns": [r"api.*key.*exposed", r"aws.*key", r"google.*api", r"firebase.*key"],
        "category_patterns": ["Secrets"],
        "severity_patterns": ["high", "critical"],
        "entry_point_type": "hardcoded_credential",
        "target_types": ["backend_compromise", "data_theft", "financial_fraud"],
        "mitre_mobile": ["T1552"],
        "exploitability": "easy",
        "confidence": 0.9,
        "requires_physical": False,
        "skill_level": "novice",
        "enables": ["api_abuse", "cloud_access"],
        "description": "Exposed API keys allow accessing backend services",
    },
    "exposed_db_connection_to_compromise": {
        "name": "Database Connection String Compromise",
        "check_patterns": [r"database.*connection", r"mongodb://", r"postgres://", r"mysql://"],
        "category_patterns": ["Secrets"],
        "severity_patterns": ["critical"],
        "entry_point_type": "hardcoded_credential",
        "target_types": ["backend_compromise", "data_theft"],
        "mitre_mobile": ["T1552"],
        "exploitability": "easy",
        "confidence": 0.95,
        "requires_physical": False,
        "skill_level": "novice",
        "enables": ["database_access", "data_theft"],
        "description": "Exposed database connection allows direct database access",
    },

    # === Injection Edges ===
    "sql_injection_to_data_theft": {
        "name": "SQL Injection Data Theft",
        "check_patterns": [r"sql.*injection", r"rawquery.*concat"],
        "category_patterns": ["SQL Injection"],
        "severity_patterns": ["high", "critical"],
        "entry_point_type": None,
        "target_types": ["data_theft", "data_manipulation"],
        "mitre_mobile": ["T1409"],
        "exploitability": "moderate",
        "confidence": 0.8,
        "requires_physical": False,
        "skill_level": "intermediate",
        "enables": ["database_read", "database_write"],
        "description": "SQL injection allows reading/writing database",
    },
    "command_injection_to_code_execution": {
        "name": "Command Injection Code Execution",
        "check_patterns": [r"command.*injection", r"runtime.*exec"],
        "category_patterns": ["Command Injection"],
        "severity_patterns": ["critical"],
        "entry_point_type": None,
        "target_types": ["code_execution"],
        "mitre_mobile": ["T1624"],
        "exploitability": "moderate",
        "confidence": 0.85,
        "requires_physical": False,
        "skill_level": "intermediate",
        "enables": ["shell_access", "code_execution"],
        "description": "Command injection allows arbitrary command execution",
    },

    # === Deep Link Edges ===
    "deep_link_to_data_theft": {
        "name": "Deep Link Parameter Theft",
        "check_patterns": [r"custom.*scheme", r"deep.*link", r"url.*scheme"],
        "category_patterns": ["Deep Links"],
        "severity_patterns": ["medium", "high"],
        "entry_point_type": "deep_link",
        "target_types": ["credential_theft", "data_theft"],
        "mitre_mobile": ["T1437"],
        "exploitability": "moderate",
        "confidence": 0.6,
        "requires_physical": False,
        "skill_level": "intermediate",
        "enables": ["url_hijacking", "parameter_theft"],
        "description": "Custom URL schemes can be hijacked to steal data",
    },

    # === iOS Specific Edges ===
    "ats_disabled_to_mitm": {
        "name": "ATS Disabled to MITM",
        "check_patterns": [r"ats.*disabled", r"nsallowsarbitraryloads"],
        "category_patterns": ["Network Security"],
        "severity_patterns": ["high"],
        "entry_point_type": "cleartext_network",
        "target_types": ["credential_theft", "session_hijacking"],
        "mitre_mobile": ["T1439"],
        "exploitability": "easy",
        "confidence": 0.9,
        "requires_physical": False,
        "requires_network": True,
        "skill_level": "novice",
        "enables": ["network_interception"],
        "description": "Disabled ATS allows HTTP traffic interception",
    },
    "get_task_allow_to_debug": {
        "name": "Debug Entitlement Exploitation",
        "check_patterns": [r"get-task-allow", r"debug.*entitlement"],
        "category_patterns": ["Configuration"],
        "severity_patterns": ["high"],
        "entry_point_type": "debuggable_app",
        "target_types": ["code_execution", "data_theft"],
        "mitre_mobile": ["T1407"],
        "exploitability": "moderate",
        "confidence": 0.85,
        "requires_physical": True,
        "skill_level": "advanced",
        "enables": ["debug_attach", "memory_dump"],
        "description": "get-task-allow entitlement allows debugger attachment",
    },
}


def get_edge_for_finding(
    finding_title: str,
    finding_category: str,
    finding_severity: str,
) -> list[dict[str, Any]]:
    """Find matching edge definitions for a finding.

    Args:
        finding_title: The finding's title
        finding_category: The finding's category
        finding_severity: The finding's severity

    Returns:
        List of matching edge definitions
    """
    import re

    matches = []
    title_lower = finding_title.lower()
    category_lower = finding_category.lower()
    severity_lower = finding_severity.lower()

    for edge_id, edge_def in EDGE_DEFINITIONS.items():
        # Check category patterns
        category_match = any(
            cat.lower() in category_lower
            for cat in edge_def.get("category_patterns", [])
        )

        # Check title patterns
        title_match = any(
            re.search(pattern, title_lower)
            for pattern in edge_def.get("check_patterns", [])
        )

        # Check severity patterns
        severity_match = severity_lower in edge_def.get("severity_patterns", [])

        # Match if category and (title or severity) match
        if category_match and (title_match or severity_match):
            matches.append({"edge_id": edge_id, **edge_def})

    return matches

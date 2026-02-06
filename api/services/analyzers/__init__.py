"""Static and dynamic security analyzers for mobile application analysis.

This package contains all security analyzer implementations that are
registered with the scan orchestrator to perform automated vulnerability
detection on Android and iOS applications.

Analyzer categories:
    - **Manifest/Config**: ManifestAnalyzer, PlistAnalyzer, EntitlementsAnalyzer,
      BackupAnalyzer, NetworkSecurityConfigAnalyzer
    - **Binary Analysis**: DexAnalyzer, NativeLibAnalyzer, iOSBinaryAnalyzer,
      BinaryProtectionAnalyzer, ObfuscationAnalyzer
    - **Code Quality**: CodeQualityAnalyzer, LoggingAnalyzer, SecretScanner
    - **Cryptography**: CryptoAuditor, SSLPinningAnalyzer
    - **Platform Security**: PermissionsAnalyzer, ComponentSecurityAnalyzer,
      IPCScanner, DeeplinkAnalyzer, WebViewAuditor
    - **Data Protection**: SecureStorageAnalyzer, DataLeakageAnalyzer
    - **Privacy**: PrivacyAnalyzer
    - **Authentication**: AuthenticationAnalyzer, FirebaseAnalyzer
    - **Network**: NetworkAnalyzer, ApiEndpointExtractor
    - **Framework-Specific**: FlutterAnalyzer, ReactNativeAnalyzer
    - **Dynamic**: RuntimeAnalyzer, NetworkAnalyzer
    - **Dependencies**: DependencyAnalyzer, ResourceAnalyzer
"""

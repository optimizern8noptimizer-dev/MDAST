from dataclasses import dataclass, field
from typing import Pattern
import re


@dataclass
class SastRule:
    rule_id:      str
    title:        str
    description:  str
    severity:     str
    cvss_score:   float
    cvss_vector:  str
    cwe_id:       str
    owasp_mobile: str
    masvs_id:     str
    pci_dss_req:  str
    patterns:     list = field(default_factory=list)
    recommendation: str = ""
    references:   str = ""


SAST_RULES = [

    SastRule(
        rule_id="SAST-001",
        title="Hardcoded API Key or Secret",
        description="A hardcoded API key or secret token was found in source code. Attackers who decompile the APK can extract and abuse these credentials.",
        severity="critical",
        cvss_score=9.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cwe_id="CWE-798",
        owasp_mobile="M1:2024",
        masvs_id="MASVS-STORAGE-2",
        pci_dss_req="6.2.4",
        patterns=[
            re.compile(r'(?i)(api[_\-]?key|apikey|secret[_\-]?key|secret)\s*[=:]\s*["\'][A-Za-z0-9+/]{16,}["\']'),
            re.compile(r'(?i)(access[_\-]?token|auth[_\-]?token)\s*[=:]\s*["\'][A-Za-z0-9\-_.]{16,}["\']'),
        ],
        recommendation="Remove all hardcoded credentials. Use Android Keystore or environment-based secret injection at build time. Rotate any exposed credentials immediately.",
        references='["https://owasp.org/www-project-mobile-top-10/", "https://cwe.mitre.org/data/definitions/798.html"]',
    ),

    SastRule(
        rule_id="SAST-002",
        title="Hardcoded Password",
        description="A hardcoded password was found in source code. This exposes authentication credentials to anyone who decompiles the APK.",
        severity="critical",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cwe_id="CWE-259",
        owasp_mobile="M1:2024",
        masvs_id="MASVS-STORAGE-2",
        pci_dss_req="6.2.4",
        patterns=[
            re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}["\']'),
            re.compile(r'(?i)(db_pass|database_password|db_password)\s*[=:]\s*["\'][^"\']{2,}["\']'),
        ],
        recommendation="Never hardcode passwords. Use Android Keystore or secure server-side authentication. Rotate exposed passwords immediately.",
        references='["https://cwe.mitre.org/data/definitions/259.html"]',
    ),

    SastRule(
        rule_id="SAST-003",
        title="Hardcoded Private Key or Certificate",
        description="A private key or certificate was found embedded in the application. This completely compromises the PKI trust chain.",
        severity="critical",
        cvss_score=9.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cwe_id="CWE-321",
        owasp_mobile="M1:2024",
        masvs_id="MASVS-CRYPTO-2",
        pci_dss_req="4.2.1",
        patterns=[
            re.compile(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----'),
            re.compile(r'-----BEGIN CERTIFICATE-----'),
        ],
        recommendation="Remove private keys from APK. Store certificates server-side. Use Android Keystore for key material that must reside on device.",
        references='["https://cwe.mitre.org/data/definitions/321.html"]',
    ),

    SastRule(
        rule_id="SAST-010",
        title="Use of Broken Hash Algorithm (MD5/SHA-1)",
        description="MD5 and SHA-1 are cryptographically broken. They are vulnerable to collision and preimage attacks.",
        severity="high",
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cwe_id="CWE-327",
        owasp_mobile="M10:2024",
        masvs_id="MASVS-CRYPTO-1",
        pci_dss_req="6.2.4",
        patterns=[
            re.compile(r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']'),
            re.compile(r'MessageDigest\.getInstance\s*\(\s*["\']SHA-1["\']'),
            re.compile(r'MessageDigest\.getInstance\s*\(\s*["\']SHA1["\']'),
        ],
        recommendation="Replace MD5/SHA-1 with SHA-256 or SHA-3. For password hashing use bcrypt, scrypt or Argon2.",
        references='["https://cwe.mitre.org/data/definitions/327.html"]',
    ),

    SastRule(
        rule_id="SAST-011",
        title="Use of Weak Cipher (DES/3DES/RC4)",
        description="DES, 3DES and RC4 are deprecated ciphers with known weaknesses.",
        severity="high",
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cwe_id="CWE-327",
        owasp_mobile="M10:2024",
        masvs_id="MASVS-CRYPTO-1",
        pci_dss_req="6.2.4",
        patterns=[
            re.compile(r'Cipher\.getInstance\s*\(\s*["\']DES["\']'),
            re.compile(r'Cipher\.getInstance\s*\(\s*["\']DESede'),
            re.compile(r'Cipher\.getInstance\s*\(\s*["\']RC4'),
        ],
        recommendation="Use AES-256-GCM for symmetric encryption.",
        references='["https://cwe.mitre.org/data/definitions/327.html"]',
    ),

    SastRule(
        rule_id="SAST-012",
        title="ECB Mode Encryption",
        description="ECB mode is deterministic and reveals patterns in plaintext.",
        severity="high",
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cwe_id="CWE-327",
        owasp_mobile="M10:2024",
        masvs_id="MASVS-CRYPTO-1",
        pci_dss_req="6.2.4",
        patterns=[
            re.compile(r'Cipher\.getInstance\s*\(\s*["\']AES/ECB'),
            re.compile(r'Cipher\.getInstance\s*\(\s*["\']AES["\']'),
        ],
        recommendation="Use AES/GCM/NoPadding with a random 96-bit IV and authentication tag.",
        references='["https://cwe.mitre.org/data/definitions/327.html"]',
    ),

    SastRule(
        rule_id="SAST-013",
        title="Insecure Random Number Generator",
        description="java.util.Random is not cryptographically secure.",
        severity="medium",
        cvss_score=5.9,
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cwe_id="CWE-330",
        owasp_mobile="M10:2024",
        masvs_id="MASVS-CRYPTO-1",
        pci_dss_req="6.2.4",
        patterns=[
            re.compile(r'new\s+Random\s*\('),
            re.compile(r'import\s+java\.util\.Random'),
            re.compile(r'Math\.random\s*\('),
        ],
        recommendation="Use java.security.SecureRandom for all cryptographic operations.",
        references='["https://cwe.mitre.org/data/definitions/330.html"]',
    ),

    SastRule(
        rule_id="SAST-020",
        title="Sensitive Data in SharedPreferences",
        description="Storing sensitive data in SharedPreferences without encryption exposes it on rooted devices.",
        severity="high",
        cvss_score=7.1,
        cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cwe_id="CWE-312",
        owasp_mobile="M2:2024",
        masvs_id="MASVS-STORAGE-1",
        pci_dss_req="3.3.1",
        patterns=[
            re.compile(r'\.putString\s*\(\s*["\'](?:password|token|secret|key|pin)["\']'),
            re.compile(r'(?i)SharedPreferences.*(?:password|token|secret|private)'),
        ],
        recommendation="Use EncryptedSharedPreferences from Jetpack Security or Android Keystore.",
        references='["https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/"]',
    ),

    SastRule(
        rule_id="SAST-021",
        title="Sensitive Data Written to External Storage",
        description="External storage is accessible by any app with READ_EXTERNAL_STORAGE permission.",
        severity="high",
        cvss_score=7.1,
        cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cwe_id="CWE-312",
        owasp_mobile="M2:2024",
        masvs_id="MASVS-STORAGE-1",
        pci_dss_req="3.3.1",
        patterns=[
            re.compile(r'getExternalStorageDirectory'),
            re.compile(r'getExternalFilesDir'),
            re.compile(r'Environment\.getExternalStorage'),
        ],
        recommendation="Store sensitive files in internal storage with MODE_PRIVATE or use EncryptedFile.",
        references='["https://cwe.mitre.org/data/definitions/312.html"]',
    ),

    SastRule(
        rule_id="SAST-022",
        title="Sensitive Data in Application Log",
        description="Logging sensitive information to Logcat is readable on rooted devices.",
        severity="medium",
        cvss_score=5.5,
        cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        cwe_id="CWE-532",
        owasp_mobile="M2:2024",
        masvs_id="MASVS-STORAGE-2",
        pci_dss_req="3.3.1",
        patterns=[
            re.compile(r'Log\.[dviwef]\s*\(.*(?:password|passwd|token|secret|pin|card|cvv)', re.IGNORECASE),
            re.compile(r'System\.out\.println.*(?:password|token|secret)', re.IGNORECASE),
            re.compile(r'printStackTrace\s*\('),
        ],
        recommendation="Remove all logging of sensitive data. Disable logging in release builds.",
        references='["https://cwe.mitre.org/data/definitions/532.html"]',
    ),

    SastRule(
        rule_id="SAST-030",
        title="Insecure HTTP Connection (Cleartext Traffic)",
        description="The application communicates over unencrypted HTTP.",
        severity="high",
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cwe_id="CWE-319",
        owasp_mobile="M5:2024",
        masvs_id="MASVS-NETWORK-1",
        pci_dss_req="4.2.1",
        patterns=[
            re.compile(r'http://(?!localhost|127\.0\.0\.1|10\.|192\.168\.)'),
            re.compile(r'android:usesCleartextTraffic\s*=\s*["\']true["\']', re.IGNORECASE),
        ],
        recommendation='Enforce HTTPS. Set android:usesCleartextTraffic="false" in AndroidManifest.xml.',
        references='["https://cwe.mitre.org/data/definitions/319.html"]',
    ),

    SastRule(
        rule_id="SAST-031",
        title="SSL/TLS Certificate Validation Disabled",
        description="The application disables SSL/TLS certificate validation, enabling MITM attacks.",
        severity="critical",
        cvss_score=9.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cwe_id="CWE-295",
        owasp_mobile="M5:2024",
        masvs_id="MASVS-NETWORK-1",
        pci_dss_req="4.2.1",
        patterns=[
            re.compile(r'X509TrustManager'),
            re.compile(r'checkClientTrusted|checkServerTrusted'),
            re.compile(r'ALLOW_ALL_HOSTNAME_VERIFIER'),
            re.compile(r'TrustAllCerts|TrustAll|InsecureTrust', re.IGNORECASE),
        ],
        recommendation="Never override certificate validation. Use certificate pinning for additional protection.",
        references='["https://cwe.mitre.org/data/definitions/295.html"]',
    ),

    SastRule(
        rule_id="SAST-032",
        title="Hostname Verification Disabled",
        description="The application disables hostname verification, enabling MITM attacks.",
        severity="high",
        cvss_score=7.4,
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cwe_id="CWE-297",
        owasp_mobile="M5:2024",
        masvs_id="MASVS-NETWORK-1",
        pci_dss_req="4.2.1",
        patterns=[
            re.compile(r'NullHostnameVerifier|AllowAllHostnameVerifier'),
            re.compile(r'setHostnameVerifier.*ALLOW_ALL'),
        ],
        recommendation="Use the default HostnameVerifier. Never return true from verify() unconditionally.",
        references='["https://cwe.mitre.org/data/definitions/297.html"]',
    ),

    SastRule(
        rule_id="SAST-040",
        title="Debuggable Application in Release",
        description='android:debuggable="true" enables ADB debugging on production builds.',
        severity="high",
        cvss_score=7.8,
        cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        cwe_id="CWE-489",
        owasp_mobile="M7:2024",
        masvs_id="MASVS-RESILIENCE-2",
        pci_dss_req="6.2.4",
        patterns=[
            re.compile(r'android:debuggable\s*=\s*["\']true["\']'),
        ],
        recommendation='Set android:debuggable="false" or remove the attribute.',
        references='["https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-2/"]',
    ),

    SastRule(
        rule_id="SAST-041",
        title="Backup Enabled — Sensitive Data Exposure Risk",
        description='android:allowBackup="true" allows ADB backup of application data without root.',
        severity="medium",
        cvss_score=5.5,
        cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        cwe_id="CWE-312",
        owasp_mobile="M2:2024",
        masvs_id="MASVS-STORAGE-1",
        pci_dss_req="3.3.1",
        patterns=[
            re.compile(r'android:allowBackup\s*=\s*["\']true["\']'),
        ],
        recommendation='Set android:allowBackup="false" for apps handling sensitive data.',
        references='["https://cwe.mitre.org/data/definitions/312.html"]',
    ),

    SastRule(
        rule_id="SAST-042",
        title="Exported Activity Without Permission",
        description="An Activity/Service/Receiver is exported without requiring permissions.",
        severity="high",
        cvss_score=7.1,
        cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cwe_id="CWE-926",
        owasp_mobile="M4:2024",
        masvs_id="MASVS-PLATFORM-1",
        pci_dss_req="6.2.4",
        patterns=[
            re.compile(r'<activity[^>]+android:exported\s*=\s*["\']true["\']'),
            re.compile(r'<service[^>]+android:exported\s*=\s*["\']true["\']'),
            re.compile(r'<receiver[^>]+android:exported\s*=\s*["\']true["\']'),
        ],
        recommendation="Add android:permission to exported components or set android:exported=false.",
        references='["https://cwe.mitre.org/data/definitions/926.html"]',
    ),

    SastRule(
        rule_id="SAST-043",
        title="Dangerous Permissions Declared",
        description="The application declares dangerous permissions beyond what is necessary.",
        severity="medium",
        cvss_score=5.5,
        cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        cwe_id="CWE-250",
        owasp_mobile="M8:2024",
        masvs_id="MASVS-PLATFORM-2",
        pci_dss_req="6.2.4",
        patterns=[
            re.compile(r'uses-permission.*RECORD_AUDIO'),
            re.compile(r'uses-permission.*READ_CONTACTS'),
            re.compile(r'uses-permission.*ACCESS_FINE_LOCATION'),
            re.compile(r'uses-permission.*READ_SMS'),
            re.compile(r'uses-permission.*CAMERA'),
            re.compile(r'uses-permission.*READ_CALL_LOG'),
        ],
        recommendation="Apply least privilege. Request only permissions strictly necessary for core functionality.",
        references='["https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-2/"]',
    ),

    SastRule(
        rule_id="SAST-050",
        title="SQL Injection Vulnerability",
        description="String concatenation used to build SQL queries allows SQL injection.",
        severity="critical",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cwe_id="CWE-89",
        owasp_mobile="M4:2024",
        masvs_id="MASVS-CODE-1",
        pci_dss_req="6.2.3",
        patterns=[
            re.compile(r'rawQuery\s*\(\s*["\'].*\+'),
            re.compile(r'execSQL\s*\(\s*["\'].*SELECT.*\+'),
            re.compile(r'execSQL\s*\(\s*["\'].*INSERT.*\+'),
        ],
        recommendation="Use parameterized queries with selectionArgs. Never concatenate user input into SQL.",
        references='["https://cwe.mitre.org/data/definitions/89.html"]',
    ),

    SastRule(
        rule_id="SAST-051",
        title="JavaScript Enabled in WebView",
        description="JavaScript enabled in WebView can lead to XSS or JavaScript Interface abuse.",
        severity="high",
        cvss_score=8.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        cwe_id="CWE-749",
        owasp_mobile="M4:2024",
        masvs_id="MASVS-PLATFORM-1",
        pci_dss_req="6.2.4",
        patterns=[
            re.compile(r'setJavaScriptEnabled\s*\(\s*true\s*\)'),
            re.compile(r'addJavascriptInterface\s*\('),
        ],
        recommendation="Disable JavaScript if not required. Validate all data passed to WebView.",
        references='["https://cwe.mitre.org/data/definitions/749.html"]',
    ),

    SastRule(
        rule_id="SAST-060",
        title="Intent with Implicit Broadcast",
        description="Implicit Intents can be intercepted by malicious applications.",
        severity="medium",
        cvss_score=6.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        cwe_id="CWE-927",
        owasp_mobile="M4:2024",
        masvs_id="MASVS-PLATFORM-1",
        pci_dss_req="6.2.4",
        patterns=[
            re.compile(r'sendBroadcast\s*\('),
        ],
        recommendation="Use explicit Intents with setPackage(). For sensitive broadcasts use permissions.",
        references='["https://cwe.mitre.org/data/definitions/927.html"]',
    ),

    SastRule(
        rule_id="SAST-061",
        title="Hardcoded IP Address",
        description="A hardcoded IP address was found. May expose internal infrastructure.",
        severity="low",
        cvss_score=3.7,
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cwe_id="CWE-547",
        owasp_mobile="M8:2024",
        masvs_id="MASVS-CODE-2",
        pci_dss_req="6.2.4",
        patterns=[
            re.compile(r'(?<!\d)(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?!\d)'),
        ],
        recommendation="Use DNS names instead of IP addresses.",
        references='["https://cwe.mitre.org/data/definitions/547.html"]',
    ),

]

RULES_BY_ID = {r.rule_id: r for r in SAST_RULES}
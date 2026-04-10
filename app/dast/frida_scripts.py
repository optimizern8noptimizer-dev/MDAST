"""
app/dast/frida_scripts.py
Frida-скрипты для динамического анализа Android приложений.

Покрытие стандартов:
  - OWASP MASVS v2.0
  - OWASP Mobile Top 10 2024
  - CWE
  - PCI DSS 4.0
"""

# ── SSL/TLS ───────────────────────────────────────────────────────────────────

SSL_BYPASS_DETECTION = """
// MASVS-NETWORK-1 | CWE-295 | M5:2024
// Обнаружение обхода SSL/TLS валидации

Java.perform(function() {

    // Hook 1: TrustManager — checkServerTrusted
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            send(JSON.stringify({
                type: 'ssl_bypass',
                severity: 'critical',
                rule_id: 'DAST-001',
                title: 'SSL Certificate Validation Bypass Detected',
                description: 'TrustManagerImpl.verifyChain was hooked — SSL pinning may be bypassed.',
                cwe_id: 'CWE-295',
                owasp_mobile: 'M5:2024',
                masvs_id: 'MASVS-NETWORK-1',
                cvss_score: 9.1,
                host: host
            }));
            return this.verifyChain(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData);
        };
    } catch(e) {}

    // Hook 2: OkHttp CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            send(JSON.stringify({
                type: 'ssl_pinning_check',
                severity: 'info',
                rule_id: 'DAST-001',
                title: 'SSL Certificate Pinning Check',
                description: 'OkHttp CertificatePinner.check called — certificate pinning is active.',
                cwe_id: 'CWE-295',
                owasp_mobile: 'M5:2024',
                masvs_id: 'MASVS-NETWORK-1',
                cvss_score: 0.0,
                hostname: hostname
            }));
            return this.check(hostname, peerCertificates);
        };
    } catch(e) {}

    // Hook 3: HttpsURLConnection — custom HostnameVerifier
    try {
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(verifier) {
            send(JSON.stringify({
                type: 'hostname_verifier',
                severity: 'high',
                rule_id: 'DAST-002',
                title: 'Custom HostnameVerifier Set',
                description: 'A custom HostnameVerifier was set on HttpsURLConnection. May disable hostname validation.',
                cwe_id: 'CWE-297',
                owasp_mobile: 'M5:2024',
                masvs_id: 'MASVS-NETWORK-1',
                cvss_score: 7.4,
                verifier_class: verifier.$className
            }));
            return this.setDefaultHostnameVerifier(verifier);
        };
    } catch(e) {}

});
"""

# ── Криптография ──────────────────────────────────────────────────────────────

CRYPTO_MONITORING = """
// MASVS-CRYPTO-1 | CWE-327 | M10:2024
// Мониторинг использования криптографических примитивов

Java.perform(function() {

    // Hook 1: Cipher.getInstance — слабые алгоритмы
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.getInstance.overload('java.lang.String').implementation = function(transformation) {
        var t = transformation.toUpperCase();
        var severity = 'info';
        var finding = null;

        if (t.indexOf('DES') !== -1 && t.indexOf('DESE') === -1) {
            severity = 'high';
            finding = {
                type: 'weak_cipher',
                severity: severity,
                rule_id: 'DAST-010',
                title: 'Weak Cipher Used at Runtime: DES',
                description: 'DES cipher detected at runtime. 56-bit key is brute-forceable.',
                cwe_id: 'CWE-327',
                owasp_mobile: 'M10:2024',
                masvs_id: 'MASVS-CRYPTO-1',
                cvss_score: 7.5,
                transformation: transformation
            };
        } else if (t.indexOf('RC4') !== -1 || t.indexOf('ARCFOUR') !== -1) {
            severity = 'high';
            finding = {
                type: 'weak_cipher',
                severity: severity,
                rule_id: 'DAST-010',
                title: 'Weak Cipher Used at Runtime: RC4',
                description: 'RC4 has statistical biases and must not be used.',
                cwe_id: 'CWE-327',
                owasp_mobile: 'M10:2024',
                masvs_id: 'MASVS-CRYPTO-1',
                cvss_score: 7.5,
                transformation: transformation
            };
        } else if (t === 'AES' || t.indexOf('AES/ECB') !== -1) {
            severity = 'high';
            finding = {
                type: 'ecb_mode',
                severity: severity,
                rule_id: 'DAST-011',
                title: 'ECB Mode Detected at Runtime',
                description: 'AES without mode specification defaults to ECB. ECB reveals plaintext patterns.',
                cwe_id: 'CWE-327',
                owasp_mobile: 'M10:2024',
                masvs_id: 'MASVS-CRYPTO-1',
                cvss_score: 7.5,
                transformation: transformation
            };
        }

        if (finding) {
            send(JSON.stringify(finding));
        }
        return this.getInstance(transformation);
    };

    // Hook 2: MessageDigest.getInstance — MD5/SHA1
    var MessageDigest = Java.use('java.security.MessageDigest');
    MessageDigest.getInstance.overload('java.lang.String').implementation = function(algorithm) {
        var alg = algorithm.toUpperCase();
        if (alg === 'MD5' || alg === 'SHA-1' || alg === 'SHA1') {
            send(JSON.stringify({
                type: 'broken_hash',
                severity: 'high',
                rule_id: 'DAST-012',
                title: 'Broken Hash Algorithm at Runtime: ' + algorithm,
                description: algorithm + ' is cryptographically broken and must not be used for security purposes.',
                cwe_id: 'CWE-327',
                owasp_mobile: 'M10:2024',
                masvs_id: 'MASVS-CRYPTO-1',
                cvss_score: 7.5,
                algorithm: algorithm
            }));
        }
        return this.getInstance(algorithm);
    };

    // Hook 3: SecretKeySpec — короткие ключи
    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(keyBytes, algorithm) {
        var keyLenBits = keyBytes.length * 8;
        if (algorithm.toUpperCase().indexOf('AES') !== -1 && keyLenBits < 256) {
            send(JSON.stringify({
                type: 'short_key',
                severity: 'medium',
                rule_id: 'DAST-013',
                title: 'Short Encryption Key: ' + keyLenBits + '-bit AES',
                description: 'AES key length is ' + keyLenBits + ' bits. Minimum recommended: 256 bits.',
                cwe_id: 'CWE-326',
                owasp_mobile: 'M10:2024',
                masvs_id: 'MASVS-CRYPTO-1',
                cvss_score: 5.9,
                key_length_bits: keyLenBits,
                algorithm: algorithm
            }));
        }
        return this.$init(keyBytes, algorithm);
    };

    // Hook 4: Random vs SecureRandom
    var Random = Java.use('java.util.Random');
    Random.$init.overload().implementation = function() {
        send(JSON.stringify({
            type: 'insecure_random',
            severity: 'medium',
            rule_id: 'DAST-014',
            title: 'Insecure Random Used at Runtime',
            description: 'java.util.Random instantiated at runtime. Must not be used for security-sensitive values.',
            cwe_id: 'CWE-330',
            owasp_mobile: 'M10:2024',
            masvs_id: 'MASVS-CRYPTO-1',
            cvss_score: 5.9
        }));
        return this.$init();
    };

});
"""

# ── Хранилище данных ──────────────────────────────────────────────────────────

DATA_STORAGE_MONITORING = """
// MASVS-STORAGE-1 | CWE-312 | M2:2024
// Мониторинг хранения чувствительных данных

Java.perform(function() {

    var SENSITIVE_KEYS = ['password', 'passwd', 'token', 'secret', 'key', 'pin',
                          'card', 'cvv', 'ssn', 'private', 'credential', 'auth'];

    function isSensitive(str) {
        if (!str) return false;
        var s = str.toLowerCase();
        for (var i = 0; i < SENSITIVE_KEYS.length; i++) {
            if (s.indexOf(SENSITIVE_KEYS[i]) !== -1) return true;
        }
        return false;
    }

    // Hook 1: SharedPreferences.putString
    try {
        var SharedPreferencesEditor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
        SharedPreferencesEditor.putString.implementation = function(key, value) {
            if (isSensitive(key) || isSensitive(value)) {
                send(JSON.stringify({
                    type: 'insecure_storage',
                    severity: 'high',
                    rule_id: 'DAST-020',
                    title: 'Sensitive Data in SharedPreferences',
                    description: 'Sensitive key "' + key + '" stored in unencrypted SharedPreferences.',
                    cwe_id: 'CWE-312',
                    owasp_mobile: 'M2:2024',
                    masvs_id: 'MASVS-STORAGE-1',
                    cvss_score: 7.1,
                    key: key
                }));
            }
            return this.putString(key, value);
        };
    } catch(e) {}

    // Hook 2: File write to external storage
    try {
        var FileOutputStream = Java.use('java.io.FileOutputStream');
        FileOutputStream.$init.overload('java.lang.String').implementation = function(path) {
            if (path && (path.indexOf('/sdcard') !== -1 || path.indexOf('/external') !== -1)) {
                send(JSON.stringify({
                    type: 'external_storage_write',
                    severity: 'high',
                    rule_id: 'DAST-021',
                    title: 'File Written to External Storage',
                    description: 'Data written to external storage: ' + path,
                    cwe_id: 'CWE-312',
                    owasp_mobile: 'M2:2024',
                    masvs_id: 'MASVS-STORAGE-1',
                    cvss_score: 7.1,
                    file_path: path
                }));
            }
            return this.$init(path);
        };
    } catch(e) {}

    // Hook 3: Log.d/v/i — утечка данных в лог
    try {
        var Log = Java.use('android.util.Log');
        ['d', 'v', 'i', 'w', 'e'].forEach(function(level) {
            try {
                Log[level].overload('java.lang.String', 'java.lang.String').implementation = function(tag, msg) {
                    if (isSensitive(msg) || isSensitive(tag)) {
                        send(JSON.stringify({
                            type: 'sensitive_log',
                            severity: 'medium',
                            rule_id: 'DAST-022',
                            title: 'Sensitive Data in Log',
                            description: 'Potentially sensitive data logged at level ' + level.toUpperCase(),
                            cwe_id: 'CWE-532',
                            owasp_mobile: 'M2:2024',
                            masvs_id: 'MASVS-STORAGE-2',
                            cvss_score: 5.5,
                            tag: tag,
                            level: level
                        }));
                    }
                    return this[level](tag, msg);
                };
            } catch(e2) {}
        });
    } catch(e) {}

    // Hook 4: SQLite — незашифрованные запросы с чувствительными данными
    try {
        var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
        SQLiteDatabase.execSQL.overload('java.lang.String').implementation = function(sql) {
            if (isSensitive(sql)) {
                send(JSON.stringify({
                    type: 'sqlite_sensitive',
                    severity: 'medium',
                    rule_id: 'DAST-023',
                    title: 'Sensitive Data in SQLite Query',
                    description: 'SQLite query may contain sensitive column names or values.',
                    cwe_id: 'CWE-312',
                    owasp_mobile: 'M2:2024',
                    masvs_id: 'MASVS-STORAGE-1',
                    cvss_score: 5.5
                }));
            }
            return this.execSQL(sql);
        };
    } catch(e) {}

});
"""

# ── Сетевой трафик ────────────────────────────────────────────────────────────

NETWORK_MONITORING = """
// MASVS-NETWORK-1 | CWE-319 | M5:2024
// Мониторинг сетевых соединений

Java.perform(function() {

    // Hook 1: URL.openConnection — HTTP без TLS
    try {
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function() {
            var urlStr = this.toString();
            if (urlStr.startsWith('http://')) {
                send(JSON.stringify({
                    type: 'cleartext_traffic',
                    severity: 'high',
                    rule_id: 'DAST-030',
                    title: 'Cleartext HTTP Connection',
                    description: 'Unencrypted HTTP connection opened to: ' + urlStr,
                    cwe_id: 'CWE-319',
                    owasp_mobile: 'M5:2024',
                    masvs_id: 'MASVS-NETWORK-1',
                    cvss_score: 7.5,
                    url: urlStr
                }));
            }
            return this.openConnection();
        };
    } catch(e) {}

    // Hook 2: OkHttp — перехват запросов
    try {
        var Request = Java.use('okhttp3.Request');
        var Builder = Java.use('okhttp3.Request$Builder');
        Builder.build.implementation = function() {
            var req = this.build();
            var url = req.url().toString();
            if (url.startsWith('http://')) {
                send(JSON.stringify({
                    type: 'cleartext_traffic_okhttp',
                    severity: 'high',
                    rule_id: 'DAST-030',
                    title: 'Cleartext HTTP via OkHttp',
                    description: 'OkHttp request to unencrypted endpoint: ' + url,
                    cwe_id: 'CWE-319',
                    owasp_mobile: 'M5:2024',
                    masvs_id: 'MASVS-NETWORK-1',
                    cvss_score: 7.5,
                    url: url,
                    method: req.method()
                }));
            }
            return req;
        };
    } catch(e) {}

    // Hook 3: Перехват Authorization заголовков
    try {
        var Builder2 = Java.use('okhttp3.Request$Builder');
        Builder2.addHeader.implementation = function(name, value) {
            if (name.toLowerCase() === 'authorization') {
                send(JSON.stringify({
                    type: 'auth_header',
                    severity: 'info',
                    rule_id: 'DAST-031',
                    title: 'Authorization Header Captured',
                    description: 'Authorization header observed in network request.',
                    cwe_id: 'CWE-319',
                    owasp_mobile: 'M5:2024',
                    masvs_id: 'MASVS-NETWORK-2',
                    cvss_score: 0.0,
                    header_name: name,
                    value_prefix: value.substring(0, 10) + '...'
                }));
            }
            return this.addHeader(name, value);
        };
    } catch(e) {}

});
"""

# ── Root / Tamper Detection ───────────────────────────────────────────────────

ROOT_DETECTION_MONITORING = """
// MASVS-RESILIENCE-1 | CWE-919 | M7:2024
// Мониторинг защиты от рутирования и модификации

Java.perform(function() {

    // Hook: Проверки root через exec
    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
            if (cmd && (cmd.indexOf('su') !== -1 || cmd.indexOf('busybox') !== -1)) {
                send(JSON.stringify({
                    type: 'root_check',
                    severity: 'info',
                    rule_id: 'DAST-040',
                    title: 'Root Detection Check via exec()',
                    description: 'Application checks for root via Runtime.exec: ' + cmd,
                    cwe_id: 'CWE-919',
                    owasp_mobile: 'M7:2024',
                    masvs_id: 'MASVS-RESILIENCE-1',
                    cvss_score: 0.0,
                    command: cmd
                }));
            }
            return this.exec(cmd);
        };
    } catch(e) {}

    // Hook: Проверка наличия файлов root (su, Magisk)
    try {
        var File = Java.use('java.io.File');
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            var rootPaths = ['/su/bin/su', '/system/bin/su', '/system/xbin/su',
                             '/sbin/su', '/data/local/su', '/data/local/xbin/su',
                             '/system/app/Superuser.apk', '/system/app/Magisk'];
            for (var i = 0; i < rootPaths.length; i++) {
                if (path === rootPaths[i]) {
                    send(JSON.stringify({
                        type: 'root_file_check',
                        severity: 'info',
                        rule_id: 'DAST-040',
                        title: 'Root File Detection Check',
                        description: 'Application checks for root indicator file: ' + path,
                        cwe_id: 'CWE-919',
                        owasp_mobile: 'M7:2024',
                        masvs_id: 'MASVS-RESILIENCE-1',
                        cvss_score: 0.0,
                        checked_path: path
                    }));
                    break;
                }
            }
            return this.exists();
        };
    } catch(e) {}

});
"""

# ── Clipboard ─────────────────────────────────────────────────────────────────

CLIPBOARD_MONITORING = """
// MASVS-PLATFORM-4 | CWE-200 | M8:2024
// Мониторинг буфера обмена

Java.perform(function() {
    try {
        var ClipboardManager = Java.use('android.content.ClipboardManager');
        ClipboardManager.setPrimaryClip.implementation = function(clip) {
            var text = '';
            try { text = clip.getItemAt(0).getText().toString(); } catch(e) {}
            send(JSON.stringify({
                type: 'clipboard_write',
                severity: 'medium',
                rule_id: 'DAST-050',
                title: 'Data Written to Clipboard',
                description: 'Application wrote data to system clipboard. May expose sensitive info.',
                cwe_id: 'CWE-200',
                owasp_mobile: 'M8:2024',
                masvs_id: 'MASVS-PLATFORM-4',
                cvss_score: 4.3,
                data_length: text.length
            }));
            return this.setPrimaryClip(clip);
        };
    } catch(e) {}
});
"""

# Полный объединённый скрипт для одновременного запуска
FULL_DAST_SCRIPT = "\n\n".join([
    SSL_BYPASS_DETECTION,
    CRYPTO_MONITORING,
    DATA_STORAGE_MONITORING,
    NETWORK_MONITORING,
    ROOT_DETECTION_MONITORING,
    CLIPBOARD_MONITORING,
])

# Маппинг правил для сохранения в БД
DAST_RULE_DEFAULTS = {
    "DAST-001": {"severity": "critical", "cvss_score": 9.1, "cwe_id": "CWE-295",
                 "owasp_mobile": "M5:2024", "masvs_id": "MASVS-NETWORK-1", "pci_dss_req": "4.2.1"},
    "DAST-002": {"severity": "high",     "cvss_score": 7.4, "cwe_id": "CWE-297",
                 "owasp_mobile": "M5:2024", "masvs_id": "MASVS-NETWORK-1", "pci_dss_req": "4.2.1"},
    "DAST-010": {"severity": "high",     "cvss_score": 7.5, "cwe_id": "CWE-327",
                 "owasp_mobile": "M10:2024", "masvs_id": "MASVS-CRYPTO-1", "pci_dss_req": "6.2.4"},
    "DAST-011": {"severity": "high",     "cvss_score": 7.5, "cwe_id": "CWE-327",
                 "owasp_mobile": "M10:2024", "masvs_id": "MASVS-CRYPTO-1", "pci_dss_req": "6.2.4"},
    "DAST-012": {"severity": "high",     "cvss_score": 7.5, "cwe_id": "CWE-327",
                 "owasp_mobile": "M10:2024", "masvs_id": "MASVS-CRYPTO-1", "pci_dss_req": "6.2.4"},
    "DAST-013": {"severity": "medium",   "cvss_score": 5.9, "cwe_id": "CWE-326",
                 "owasp_mobile": "M10:2024", "masvs_id": "MASVS-CRYPTO-1", "pci_dss_req": "6.2.4"},
    "DAST-014": {"severity": "medium",   "cvss_score": 5.9, "cwe_id": "CWE-330",
                 "owasp_mobile": "M10:2024", "masvs_id": "MASVS-CRYPTO-1", "pci_dss_req": "6.2.4"},
    "DAST-020": {"severity": "high",     "cvss_score": 7.1, "cwe_id": "CWE-312",
                 "owasp_mobile": "M2:2024", "masvs_id": "MASVS-STORAGE-1", "pci_dss_req": "3.3.1"},
    "DAST-021": {"severity": "high",     "cvss_score": 7.1, "cwe_id": "CWE-312",
                 "owasp_mobile": "M2:2024", "masvs_id": "MASVS-STORAGE-1", "pci_dss_req": "3.3.1"},
    "DAST-022": {"severity": "medium",   "cvss_score": 5.5, "cwe_id": "CWE-532",
                 "owasp_mobile": "M2:2024", "masvs_id": "MASVS-STORAGE-2", "pci_dss_req": "3.3.1"},
    "DAST-023": {"severity": "medium",   "cvss_score": 5.5, "cwe_id": "CWE-312",
                 "owasp_mobile": "M2:2024", "masvs_id": "MASVS-STORAGE-1", "pci_dss_req": "3.3.1"},
    "DAST-030": {"severity": "high",     "cvss_score": 7.5, "cwe_id": "CWE-319",
                 "owasp_mobile": "M5:2024", "masvs_id": "MASVS-NETWORK-1", "pci_dss_req": "4.2.1"},
    "DAST-031": {"severity": "info",     "cvss_score": 0.0, "cwe_id": "CWE-319",
                 "owasp_mobile": "M5:2024", "masvs_id": "MASVS-NETWORK-2", "pci_dss_req": "4.2.1"},
    "DAST-040": {"severity": "info",     "cvss_score": 0.0, "cwe_id": "CWE-919",
                 "owasp_mobile": "M7:2024", "masvs_id": "MASVS-RESILIENCE-1", "pci_dss_req": "6.2.4"},
    "DAST-050": {"severity": "medium",   "cvss_score": 4.3, "cwe_id": "CWE-200",
                 "owasp_mobile": "M8:2024", "masvs_id": "MASVS-PLATFORM-4", "pci_dss_req": "3.3.1"},
}
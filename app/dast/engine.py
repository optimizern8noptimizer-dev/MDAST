"""
app/dast/engine.py
DAST Engine: динамический анализ через ADB + Frida.

Шаги:
  1. ADB: подключение к устройству, получение device_id
  2. ADB: установка APK на устройство
  3. ADB: извлечение package name из APK
  4. Frida: инжект скриптов и сбор findings
  5. ADB: удаление APK с устройства (cleanup)
  6. Возврат списка findings
"""
import json
import logging
import platform
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Поиск ADB ─────────────────────────────────────────────────────────────────

def _find_adb() -> str | None:
    candidates = ["adb"]
    if platform.system() == "Windows":
        candidates = ["adb.exe", "adb"]
    for c in candidates:
        path = shutil.which(c)
        if path:
            return path
    return None


# ── Структура результата ──────────────────────────────────────────────────────

@dataclass
class DastFinding:
    rule_id:        str
    title:          str
    description:    str
    severity:       str
    cvss_score:     float
    cvss_vector:    str = ""
    cwe_id:         str = ""
    owasp_mobile:   str = ""
    masvs_id:       str = ""
    pci_dss_req:    str = ""
    frida_output:   str | None = None
    network_capture: str | None = None
    recommendation: str = ""
    references:     str = ""


# ── ADB Helper ────────────────────────────────────────────────────────────────

class AdbHelper:
    """Обёртка над ADB командами."""

    def __init__(self, device_id: str | None = None):
        self.adb = _find_adb()
        if not self.adb:
            raise RuntimeError(
                "ADB not found in PATH. "
                "Install Android Platform Tools and add to PATH."
            )
        self.device_id = device_id

    def _cmd(self, *args, timeout: int = 30) -> tuple[int, str, str]:
        """Выполнить ADB команду. Возвращает (returncode, stdout, stderr)."""
        cmd = [self.adb]
        if self.device_id:
            cmd += ["-s", self.device_id]
        cmd += list(args)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.returncode, result.stdout.strip(), result.stderr.strip()
        except subprocess.TimeoutExpired:
            return -1, "", f"Command timed out after {timeout}s"
        except Exception as e:
            return -1, "", str(e)

    def get_devices(self) -> list[dict]:
        """Получить список подключённых устройств."""
        rc, out, _ = self._cmd("devices", "-l")
        devices = []
        for line in out.splitlines()[1:]:
            line = line.strip()
            if not line or "offline" in line:
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "device":
                device_id = parts[0]
                model = next((p.split(":")[1] for p in parts if p.startswith("model:")), "unknown")
                devices.append({"id": device_id, "model": model})
        return devices

    def install_apk(self, apk_path: str) -> bool:
        """Установить APK на устройство."""
        rc, out, err = self._cmd("install", "-r", "-t", apk_path, timeout=120)
        if rc != 0:
            logger.error(f"[DAST] APK install failed: {err}")
            return False
        logger.info(f"[DAST] APK installed: {out}")
        return True

    def uninstall_apk(self, package_name: str) -> bool:
        """Удалить APK с устройства."""
        rc, out, err = self._cmd("uninstall", package_name, timeout=30)
        return rc == 0

    def start_app(self, package_name: str, activity: str | None = None) -> bool:
        """Запустить приложение через ADB."""
        if activity:
            component = f"{package_name}/{activity}"
        else:
            component = f"{package_name}/.MainActivity"

        rc, out, err = self._cmd(
            "shell", "am", "start", "-n", component,
            timeout=15
        )
        if rc != 0 or "Error" in out:
            # Попробовать запустить без activity
            rc, out, err = self._cmd(
                "shell", "monkey", "-p", package_name,
                "-c", "android.intent.category.LAUNCHER", "1",
                timeout=15
            )
        return rc == 0

    def stop_app(self, package_name: str) -> bool:
        """Остановить приложение."""
        rc, _, _ = self._cmd("shell", "am", "force-stop", package_name)
        return rc == 0

    def get_package_name(self, apk_path: str) -> str | None:
        """Извлечь package name из APK через aapt или apktool."""
        # Попробовать aapt
        aapt = shutil.which("aapt") or shutil.which("aapt.exe")
        if aapt:
            try:
                result = subprocess.run(
                    [aapt, "dump", "badging", apk_path],
                    capture_output=True, text=True, timeout=30
                )
                for line in result.stdout.splitlines():
                    if line.startswith("package:"):
                        for part in line.split():
                            if part.startswith("name="):
                                return part.split("=")[1].strip("'\"")
            except Exception:
                pass

        # Попробовать через ADB без установки
        rc, out, _ = self._cmd(
            "shell", "pm", "list", "packages", "-f",
            timeout=10
        )
        return None

    def get_logcat(self, package_name: str, duration: int = 10) -> str:
        """Собрать logcat за N секунд."""
        rc, out, _ = self._cmd(
            "logcat", "-d", "-v", "time",
            f"*:V",
            timeout=duration + 5
        )
        # Фильтровать по package
        lines = [l for l in out.splitlines()
                 if package_name in l or "AndroidRuntime" in l]
        return "\n".join(lines[:200])  # max 200 строк

    def check_device_rooted(self) -> bool:
        """Проверить наличие root на устройстве."""
        rc, out, _ = self._cmd("shell", "which", "su")
        return rc == 0 and bool(out.strip())

    def push_frida_server(self, frida_server_path: str) -> bool:
        """Загрузить frida-server на устройство."""
        rc, _, err = self._cmd(
            "push", frida_server_path, "/data/local/tmp/frida-server",
            timeout=60
        )
        if rc != 0:
            logger.error(f"[DAST] frida-server push failed: {err}")
            return False
        # Сделать исполняемым
        rc, _, _ = self._cmd("shell", "chmod", "755", "/data/local/tmp/frida-server")
        return rc == 0


# ── DAST Engine ───────────────────────────────────────────────────────────────

class DastEngine:

    def __init__(
        self,
        apk_path: str,
        package_name: str,
        device_id: str | None = None,
        timeout_seconds: int = 300,
        frida_server_path: str | None = None,
    ):
        self.apk_path = Path(apk_path)
        self.package_name = package_name
        self.timeout_seconds = timeout_seconds
        self.frida_server_path = frida_server_path
        self.findings: list[DastFinding] = []
        self._findings_lock = threading.Lock()

        self.adb = AdbHelper(device_id)
        self.device_id = device_id

    def run(self, progress_callback=None) -> list[DastFinding]:
        """
        Запустить DAST анализ.
        Требует подключённого Android устройства с root (для Frida).
        """
        def _progress(step: str, pct: int):
            if progress_callback:
                progress_callback(step, pct)
            logger.info(f"[DAST] {pct}% — {step}")

        try:
            _progress("Checking device connection", 5)
            self._check_device()

            _progress("Installing APK on device", 15)
            self._install_apk()

            _progress("Starting Frida instrumentation", 30)
            self._run_frida_analysis(progress_callback)

            _progress("Collecting logcat", 80)
            self._collect_logcat_findings()

            _progress("Cleanup — removing APK", 90)
            self._cleanup()

            _progress("Analysis complete", 100)

        except Exception as e:
            logger.error(f"[DAST] Error: {e}", exc_info=True)
            try:
                self._cleanup()
            except Exception:
                pass
            raise

        # Дедупликация
        seen = set()
        unique = []
        for f in self.findings:
            key = (f.rule_id, f.title)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        self.findings = unique
        return self.findings

    def _check_device(self):
        devices = self.adb.get_devices()
        if not devices:
            raise RuntimeError(
                "No Android device connected via ADB. "
                "Connect device with USB debugging enabled."
            )
        logger.info(f"[DAST] Devices found: {devices}")
        if not self.device_id:
            self.device_id = devices[0]["id"]
            self.adb.device_id = self.device_id
            logger.info(f"[DAST] Using device: {self.device_id}")

    def _install_apk(self):
        ok = self.adb.install_apk(str(self.apk_path))
        if not ok:
            raise RuntimeError(f"Failed to install APK: {self.apk_path}")

    def _run_frida_analysis(self, progress_callback=None):
        """Инжектировать Frida скрипты и собрать findings."""
        try:
            import frida
        except ImportError:
            raise RuntimeError(
                "frida Python package not installed. "
                "Run: pip install frida frida-tools"
            )

        from app.dast.frida_scripts import FULL_DAST_SCRIPT, DAST_RULE_DEFAULTS

        def on_message(message, data):
            """Callback при получении сообщения от Frida скрипта."""
            if message.get("type") != "send":
                return
            try:
                payload = json.loads(message["payload"])
                self._process_frida_message(payload, DAST_RULE_DEFAULTS)
            except Exception as e:
                logger.warning(f"[DAST] Cannot parse Frida message: {e}")

        # Попробовать подключиться через USB
        try:
            device = frida.get_usb_device(timeout=10)
        except Exception as e:
            raise RuntimeError(f"Cannot connect to Frida on device: {e}. "
                               "Ensure frida-server is running on device.")

        # Запустить приложение
        logger.info(f"[DAST] Spawning {self.package_name}")
        try:
            pid = device.spawn([self.package_name])
            session = device.attach(pid)
            script = session.create_script(FULL_DAST_SCRIPT)
            script.on("message", on_message)
            script.load()
            device.resume(pid)

            # Ждать указанное время пока приложение работает
            logger.info(f"[DAST] App running — collecting data for {self.timeout_seconds}s")
            time.sleep(self.timeout_seconds)

            script.unload()
            session.detach()
            device.kill(pid)

        except frida.ProcessNotFoundError:
            # Приложение уже запущено — attach
            try:
                session = device.attach(self.package_name)
                script = session.create_script(FULL_DAST_SCRIPT)
                script.on("message", on_message)
                script.load()
                time.sleep(self.timeout_seconds)
                script.unload()
                session.detach()
            except Exception as e:
                raise RuntimeError(f"Cannot attach Frida to {self.package_name}: {e}")

    def _process_frida_message(self, payload: dict, rule_defaults: dict):
        """Преобразовать Frida сообщение в DastFinding."""
        rule_id = payload.get("rule_id", "DAST-000")
        defaults = rule_defaults.get(rule_id, {})

        finding = DastFinding(
            rule_id=rule_id,
            title=payload.get("title", "Unknown Finding"),
            description=payload.get("description", ""),
            severity=payload.get("severity", defaults.get("severity", "info")),
            cvss_score=float(payload.get("cvss_score", defaults.get("cvss_score", 0.0))),
            cwe_id=payload.get("cwe_id", defaults.get("cwe_id", "")),
            owasp_mobile=payload.get("owasp_mobile", defaults.get("owasp_mobile", "")),
            masvs_id=payload.get("masvs_id", defaults.get("masvs_id", "")),
            pci_dss_req=defaults.get("pci_dss_req", ""),
            frida_output=json.dumps(payload, ensure_ascii=False),
            recommendation=self._get_recommendation(rule_id),
            references=self._get_references(rule_id),
        )

        with self._findings_lock:
            self.findings.append(finding)
            logger.info(f"[DAST] [{finding.severity.upper()}] {finding.title}")

    def _collect_logcat_findings(self):
        """Анализ logcat на утечку чувствительных данных."""
        logcat = self.adb.get_logcat(self.package_name, duration=5)
        if not logcat:
            return

        sensitive_keywords = [
            "password", "passwd", "token", "secret", "api_key",
            "credit", "card", "cvv", "private_key",
        ]
        found_keywords = [kw for kw in sensitive_keywords if kw in logcat.lower()]

        if found_keywords:
            self.findings.append(DastFinding(
                rule_id="DAST-022",
                title="Sensitive Keywords in Logcat",
                description=(
                    f"Logcat contains potentially sensitive keywords: {', '.join(found_keywords)}. "
                    "Sensitive data may be leaked through application logs."
                ),
                severity="medium",
                cvss_score=5.5,
                cwe_id="CWE-532",
                owasp_mobile="M2:2024",
                masvs_id="MASVS-STORAGE-2",
                pci_dss_req="3.3.1",
                frida_output=f"Keywords found: {found_keywords}",
                network_capture=logcat[:2000],
                recommendation="Disable all logging in release builds. Remove Log.d/v/i calls with sensitive data.",
                references='["https://cwe.mitre.org/data/definitions/532.html"]',
            ))

    def _cleanup(self):
        """Удалить APK с устройства."""
        if self.package_name:
            self.adb.stop_app(self.package_name)
            self.adb.uninstall_apk(self.package_name)
            logger.info(f"[DAST] Cleaned up: {self.package_name}")

    def _get_recommendation(self, rule_id: str) -> str:
        recommendations = {
            "DAST-001": "Remove custom TrustManager. Never disable SSL certificate validation.",
            "DAST-002": "Use default HostnameVerifier. Never return true from verify() unconditionally.",
            "DAST-010": "Replace DES/RC4 with AES-256-GCM.",
            "DAST-011": "Replace ECB mode with AES/GCM/NoPadding.",
            "DAST-012": "Replace MD5/SHA-1 with SHA-256 or SHA-3.",
            "DAST-013": "Use AES with 256-bit keys for all encryption.",
            "DAST-014": "Use java.security.SecureRandom for all security-sensitive values.",
            "DAST-020": "Use EncryptedSharedPreferences from Jetpack Security library.",
            "DAST-021": "Store sensitive files in internal storage only.",
            "DAST-022": "Remove Log.d/v/i calls. Disable logging in release builds.",
            "DAST-030": "Enforce HTTPS. Set android:usesCleartextTraffic=false.",
            "DAST-040": "Implement root detection with multiple checks.",
            "DAST-050": "Clear clipboard after sensitive operations. Disable clipboard for password fields.",
        }
        return recommendations.get(rule_id, "Review and fix according to OWASP MASVS v2.0.")

    def _get_references(self, rule_id: str) -> str:
        refs = {
            "DAST-001": '["https://cwe.mitre.org/data/definitions/295.html", "https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/"]',
            "DAST-010": '["https://cwe.mitre.org/data/definitions/327.html"]',
            "DAST-020": '["https://cwe.mitre.org/data/definitions/312.html"]',
            "DAST-030": '["https://cwe.mitre.org/data/definitions/319.html"]',
        }
        return refs.get(rule_id, '["https://mas.owasp.org/MASVS/"]')
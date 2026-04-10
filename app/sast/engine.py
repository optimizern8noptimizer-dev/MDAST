import re
import shutil
import zipfile
import logging
import subprocess
import tempfile
import platform
from pathlib import Path
from dataclasses import dataclass

from app.sast.rules import SAST_RULES

logger = logging.getLogger(__name__)


def _find_tool(name: str):
    candidates = [name]
    if platform.system() == "Windows":
        candidates = [name + ext for ext in [".bat", ".cmd", ".exe", ""]]
    for candidate in candidates:
        path = shutil.which(candidate)
        if path:
            return path
    return None


def check_tools() -> dict:
    return {
        "apktool": _find_tool("apktool") is not None,
        "jadx": _find_tool("jadx") is not None,
        "java": _find_tool("java") is not None,
    }


@dataclass
class SastFinding:
    rule_id: str
    title: str
    description: str
    severity: str
    cvss_score: float
    cvss_vector: str
    cwe_id: str
    owasp_mobile: str
    masvs_id: str
    pci_dss_req: str
    file_path: object
    line_number: object
    code_snippet: object
    recommendation: str
    references: str


class SastEngine:
    def __init__(self, apk_path: str, work_dir: str = None):
        self.apk_path = Path(apk_path)
        if not self.apk_path.exists():
            raise FileNotFoundError(f"APK not found: {apk_path}")

        if work_dir:
            self.work_dir = Path(work_dir)
            self.work_dir.mkdir(parents=True, exist_ok=True)
            self._cleanup = False
        else:
            self.work_dir = Path(tempfile.mkdtemp(prefix="masp_sast_"))
            self._cleanup = True

        self.apktool_dir = self.work_dir / "apktool_out"
        self.jadx_dir = self.work_dir / "jadx_out"
        self.findings = []

    def run(self, progress_callback=None) -> list:
        def _progress(step, pct):
            if progress_callback:
                progress_callback(step, pct)
            logger.info(f"[SAST] {pct}% — {step}")

        try:
            _progress("Extracting APK", 5)
            self._extract_apk()

            _progress("Running apktool", 15)
            self._run_apktool()

            _progress("Running jadx", 35)
            self._run_jadx()

            _progress("Analyzing AndroidManifest.xml", 55)
            self._analyze_manifest()

            _progress("Analyzing Java source code", 65)
            self._analyze_java_sources()

            _progress("Analyzing resources", 85)
            self._analyze_resources()

            _progress("Analysis complete", 100)

        except Exception as e:
            logger.error(f"[SAST] Error: {e}", exc_info=True)
            raise
        finally:
            if self._cleanup:
                shutil.rmtree(self.work_dir, ignore_errors=True)

        seen = set()
        unique = []
        for f in self.findings:
            key = (f.rule_id, f.file_path, f.line_number, (f.code_snippet or "").strip())
            if key not in seen:
                seen.add(key)
                unique.append(f)
        self.findings = unique
        return self.findings

    def _extract_apk(self):
        extract_dir = self.work_dir / "raw"
        extract_dir.mkdir(exist_ok=True)
        try:
            with zipfile.ZipFile(self.apk_path, "r") as z:
                z.extractall(extract_dir)
        except zipfile.BadZipFile as e:
            raise ValueError(f"Invalid APK file: {e}")

    def _run_apktool(self):
        apktool = _find_tool("apktool")
        if not apktool:
            logger.warning("[SAST] apktool not found — skipping")
            return
        cmd = [apktool, "d", str(self.apk_path), "-o", str(self.apktool_dir), "--force", "--no-src"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            logger.warning(f"[SAST] apktool: {result.stderr[:300]}")

    def _run_jadx(self):
        jadx = _find_tool("jadx")
        if not jadx:
            logger.warning("[SAST] jadx not found — skipping")
            return
        cmd = [jadx, str(self.apk_path), "-d", str(self.jadx_dir), "--show-bad-code", "--no-res"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            logger.warning(f"[SAST] jadx: {result.stderr[:300]}")

    def _analyze_manifest(self):
        paths = []
        if self.apktool_dir.exists():
            apktool_manifest = self.apktool_dir / "AndroidManifest.xml"
            if apktool_manifest.exists():
                paths.append(apktool_manifest)
        raw_manifest = self.work_dir / "raw" / "AndroidManifest.xml"
        if raw_manifest.exists():
            paths.append(raw_manifest)

        for manifest_path in paths:
            try:
                content = manifest_path.read_text(encoding="utf-8", errors="ignore")
                self._apply_rules_to_content(
                    content=content,
                    file_path=manifest_path.name,
                    rules_filter=lambda r: r.rule_id in {"SAST-030", "SAST-040", "SAST-041", "SAST-042", "SAST-043"},
                )
            except Exception as e:
                logger.warning(f"[SAST] Manifest read error: {e}")

    def _analyze_java_sources(self):
        if not self.jadx_dir.exists():
            logger.warning("[SAST] No jadx output — skipping Java analysis")
            return

        java_files = list(self.jadx_dir.rglob("*.java"))
        for java_file in java_files:
            str_path = str(java_file)
            if any(s in str_path for s in [
                "androidx", "android/support", "com/google/",
                "kotlin/", "kotlinx/", "okhttp3/", "retrofit2/"
            ]):
                continue
            try:
                content = java_file.read_text(encoding="utf-8", errors="ignore")
                rel_path = str(java_file.relative_to(self.jadx_dir))
                self._apply_rules_to_content(
                    content=content,
                    file_path=rel_path,
                    rules_filter=lambda r: not r.rule_id.startswith("SAST-04"),
                )
            except Exception as e:
                logger.warning(f"[SAST] File read error {java_file}: {e}")

    def _analyze_resources(self):
        dirs = [self.apktool_dir / "res", self.work_dir / "raw" / "res"]
        for base_dir in dirs:
            if not base_dir.exists():
                continue
            for res_file in base_dir.rglob("*"):
                if res_file.suffix.lower() not in {".xml", ".properties", ".json", ".txt"}:
                    continue
                try:
                    content = res_file.read_text(encoding="utf-8", errors="ignore")
                    rel_path = str(res_file.relative_to(self.work_dir))
                    resource_rules = {"SAST-001", "SAST-002"}

                    parts = {part.lower() for part in res_file.parts}
                    is_layout_file = "layout" in parts
                    is_network_config = "xml" in parts and res_file.suffix.lower() == ".xml"

                    if is_network_config:
                        resource_rules.add("SAST-030")
                    if not is_layout_file and res_file.suffix.lower() in {".properties", ".json", ".txt"}:
                        resource_rules.add("SAST-030")

                    self._apply_rules_to_content(
                        content=content,
                        file_path=rel_path,
                        rules_filter=lambda r: r.rule_id in resource_rules,
                    )
                except Exception as e:
                    logger.warning(f"[SAST] Resource error: {e}")

    def _apply_rules_to_content(self, content, file_path, rules_filter=None):
        lines = content.splitlines()
        rules = SAST_RULES
        if rules_filter:
            rules = [r for r in SAST_RULES if rules_filter(r)]

        for rule in rules:
            if rule.rule_id == "SAST-030":
                self._apply_cleartext_rule(content, file_path, lines, rule)
                continue

            for pattern in rule.patterns:
                for match in pattern.finditer(content):
                    self._append_finding(rule, file_path, lines, content, match.start())
                    break

    def _append_finding(self, rule, file_path, lines, content, start_pos: int, evidence_prefix: str | None = None):
        line_number = content[:start_pos].count("\n") + 1
        snippet_start = max(0, line_number - 3)
        snippet_end = min(len(lines), line_number + 2)
        snippet = "\n".join(
            f"{snippet_start + i + 1}: {line}"
            for i, line in enumerate(lines[snippet_start:snippet_end])
        )
        if evidence_prefix:
            snippet = f"{evidence_prefix}\n{snippet}"
        if len(snippet) > 1000:
            snippet = snippet[:1000] + "..."

        self.findings.append(SastFinding(
            rule_id=rule.rule_id,
            title=rule.title,
            description=rule.description,
            severity=rule.severity,
            cvss_score=rule.cvss_score,
            cvss_vector=rule.cvss_vector,
            cwe_id=rule.cwe_id,
            owasp_mobile=rule.owasp_mobile,
            masvs_id=rule.masvs_id,
            pci_dss_req=rule.pci_dss_req,
            file_path=file_path,
            line_number=line_number,
            code_snippet=snippet,
            recommendation=rule.recommendation,
            references=rule.references,
        ))

    def _apply_cleartext_rule(self, content, file_path, lines, rule):
        normalized_path = file_path.replace("\\", "/").lower()

        if "/layout/" in normalized_path or normalized_path.endswith(".smali"):
            return

        findings = []
        if normalized_path.endswith("androidmanifest.xml"):
            manifest_pattern = re.compile(r'android:usesCleartextTraffic\s*=\s*["\']true["\']', re.IGNORECASE)
            findings.extend((m.start(), 'Manifest allows cleartext traffic via android:usesCleartextTraffic="true".') for m in manifest_pattern.finditer(content))
        elif "/xml/" in normalized_path and normalized_path.endswith(".xml"):
            xml_pattern = re.compile(r'cleartextTrafficPermitted\s*=\s*["\']true["\']', re.IGNORECASE)
            findings.extend((m.start(), 'Network Security Config explicitly permits cleartext traffic.') for m in xml_pattern.finditer(content))
        elif normalized_path.endswith((".java", ".kt", ".json", ".properties", ".txt", ".xml")):
            http_pattern = re.compile(
                r'http://(?!localhost\b|127\.0\.0\.1\b|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[0-1])\.)[^"\'\s<>()]+',
                re.IGNORECASE,
            )
            findings.extend((m.start(), 'Application references a non-local cleartext HTTP endpoint.') for m in http_pattern.finditer(content))

        for start_pos, evidence in findings:
            self._append_finding(rule, file_path, lines, content, start_pos, evidence_prefix=evidence)

import os
import json
import re
import base64
from pathlib import Path
from typing import Dict, List, Any, Tuple, Union, Optional
from modules.hasher import calculate_sha256, calculate_entropy, refang_string, defang_string

# Attempt YARA import with graceful fallback
YARA_AVAILABLE = False
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


YARA_RULE_SOURCE = r"""
rule LostKeys_ClickFix_Lure {
    meta:
        description = "Detects GTIG 2025 COLDRIVER/Star Blizzard LOSTKEYS ClickFix attack lures and payload patterns"
        author = "Defensive Security Team"
        date = "2025-01-15"
        threat_actor = "COLDRIVER / Star Blizzard"
        mitre_tactic = "Execution, Defense Evasion, Reconnaissance"
    strings:
        $ps1 = "powershell" ascii nocase
        $ps_hidden = "-w hidden" ascii nocase
        $ps_enc = "-enc" ascii nocase
        $ps_b64 = "FromBase64String" ascii nocase
        $ps_dl = "DownloadString" ascii nocase
        $ps_iex = "iex" ascii nocase

        $recon_ip = "ipconfig" ascii nocase
        $recon_net = "net view" ascii nocase
        $recon_task = "tasklist" ascii nocase

        $ioc_domain = "cloudmediaportal" ascii nocase
        $ioc_ip = "165.227.148.68" ascii
        $ioc_tag = "LOSTKEYS" ascii nocase
        $ioc_wscript = "wscript" ascii nocase
    condition:
        any of ($ps_*) or any of ($recon_*) or any of ($ioc_*) or $ps1
}
"""

class ThreatEngine:
    """
    Core defensive analysis engine for LOSTKEYS Threat Detector.
    Evaluates suspicious script telemetry, performs IOC matching, entropy calculations,
    and maps findings to MITRE ATT&CK framework techniques.
    """

    def __init__(self, ioc_file_path: Optional[Union[str, Path]] = None) -> None:
        """
        Initializes the threat detection engine and loads the GTIG IOC database.

        :param ioc_file_path: Path to custom iocs.json file. Defaults to data/iocs.json using pathlib resolution.
        """
        if not ioc_file_path:
            base_dir = Path(__file__).resolve().parent.parent
            ioc_file_path = base_dir / "data" / "iocs.json"
        
        self.ioc_file_path: Path = Path(ioc_file_path)
        self.iocs: Dict[str, Any] = self._load_iocs()
        self.yara_compiled: Any = self._compile_yara()

    def _load_iocs(self) -> Dict[str, Any]:
        """Loads and normalizes threat indicators from JSON database using pathlib."""
        if self.ioc_file_path.exists():
            try:
                with open(self.ioc_file_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"[!] Warning: Failed to load IOC database ({self.ioc_file_path}): {e}")
        
        # Fallback default IOC structure if file is missing
        return {
            "threat_actor": "COLDRIVER / Star Blizzard (GTIG 2025)",
            "campaign": "LOSTKEYS ClickFix Attack Chain",
            "hashes": ["28a0596b9c62b7b7aca9cac2a07b067109f27d327581a60e8cb4fab92f8f4fa9"],
            "domains": ["cloudmediaportal.com", "cloudmediaportal[.]com"],
            "ips": ["165.227.148.68", "165.227.148[.]68"],
            "suspicious_strings": ["LOSTKEYS", "wscript", "ipconfig /all", "net view", "tasklist", "FromBase64String"]
        }

    def _compile_yara(self) -> Any:
        """Compiles embedded YARA rules with graceful fallback to regex if yara-python is unavailable."""
        if not YARA_AVAILABLE:
            return None
        try:
            return yara.compile(source=YARA_RULE_SOURCE)
        except Exception as e:
            print(f"[!] YARA compilation notice: {e}. Falling back to Python Regex Engine.")
            return None

    def _extract_base64_payloads(self, content: str) -> List[Dict[str, str]]:
        """Extracts and decodes inline Base64 PowerShell or encoded payloads."""
        decoded_results: List[Dict[str, str]] = []
        enc_patterns: List[str] = [
            r'(?:-enc|-encodedcommand)\s+([A-Za-z0-9+/=]{16,})',
            r'FromBase64String\s*\(\s*[\'"]([A-Za-z0-9+/=]{16,})[\'"]\s*\)'
        ]

        for pattern in enc_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for m in matches:
                try:
                    raw_bytes = base64.b64decode(m)
                    decoded_str = ""
                    try:
                        decoded_str = raw_bytes.decode('utf-16le')
                    except Exception:
                        decoded_str = raw_bytes.decode('utf-8', errors='ignore')
                    
                    if decoded_str and len(decoded_str.strip()) > 0:
                        decoded_results.append({
                            "encoded_sample": m[:30] + "..." if len(m) > 30 else m,
                            "decoded_text": decoded_str
                        })
                except Exception:
                    continue
        return decoded_results

    def analyze(self, content: Union[str, bytes], filename: str = "uploaded_sample") -> Dict[str, Any]:
        """
        Executes complete defensive threat analysis, risk scoring, and MITRE ATT&CK mapping.

        :param content: Raw artifact content (string or bytes).
        :param filename: Original sample name.
        :return: Analysis results dictionary containing score, risk level, signals, IOCs, and MITRE mappings.
        """
        if isinstance(content, bytes):
            text_content = content.decode('utf-8', errors='ignore')
            raw_bytes = content
        else:
            text_content = content
            raw_bytes = content.encode('utf-8', errors='ignore')

        # Compute hash and entropy
        file_sha256 = calculate_sha256(raw_bytes)
        entropy = calculate_entropy(raw_bytes)
        normalized_content = refang_string(text_content)

        score = 0
        detected_signals: List[Dict[str, Any]] = []
        matched_iocs: List[Dict[str, str]] = []
        mitre_mappings: List[Dict[str, str]] = []
        mitre_set = set()

        has_script_syntax = False
        has_recon_commands = False
        has_network_iocs = False

        # 1. Historical SHA-256 Hash Match Check (+60 Points)
        known_hashes = [h.lower() for h in self.iocs.get("hashes", [])]
        if file_sha256.lower() in known_hashes:
            score += 60
            detected_signals.append({
                "rule": "Known_Malware_SHA256_Match",
                "category": "Historical IOC Match",
                "points": 60,
                "evidence": f"File hash SHA-256 matched known GTIG LOSTKEYS payload: {file_sha256}"
            })
            matched_iocs.append({
                "type": "SHA-256 Hash",
                "value": file_sha256,
                "description": "Known COLDRIVER / Star Blizzard LOSTKEYS binary hash"
            })
            mitre_set.add("T1204.002")

        # 2. Historical IOC Match (Domain or IP match against iocs.json) (+50 Points per distinct category)
        known_domains = self.iocs.get("domains", [])
        for dom in known_domains:
            clean_dom = refang_string(dom)
            if clean_dom.lower() in normalized_content.lower():
                score += 50
                has_network_iocs = True
                defanged_val = defang_string(clean_dom)
                detected_signals.append({
                    "rule": "GTIG_C2_Domain_Match",
                    "category": "Historical Network IOC Match",
                    "points": 50,
                    "evidence": f"Matched documented C2 Domain: {defanged_val}"
                })
                matched_iocs.append({
                    "type": "C2 Domain",
                    "value": defanged_val,
                    "description": "GTIG 2025 LOSTKEYS Infrastructure C2 Domain"
                })

        known_ips = self.iocs.get("ips", [])
        for ip_str in known_ips:
            clean_ip = refang_string(ip_str)
            if clean_ip in normalized_content:
                score += 50
                has_network_iocs = True
                defanged_ip = defang_string(clean_ip)
                detected_signals.append({
                    "rule": "GTIG_C2_IP_Match",
                    "category": "Historical Network IOC Match",
                    "points": 50,
                    "evidence": f"Matched documented C2 IP Address: {defanged_ip}"
                })
                matched_iocs.append({
                    "type": "C2 IP",
                    "value": defanged_ip,
                    "description": "GTIG 2025 LOSTKEYS Command & Control Server IP"
                })

        # 3. Suspicious PowerShell/Script syntax (+20 Points)
        script_patterns = [
            (r'powershell(?:\.exe)?', "PowerShell Execution", "T1059.001"),
            (r'-\w*\s*hidden', "Hidden Window Flag (-w hidden)", "T1059.001"),
            (r'-enc(?:odedcommand)?', "Encoded Command Flag (-enc)", "T1059.001"),
            (r'downloadstring', "Remote Script Download (DownloadString)", "T1059.001"),
            (r'\biex\b|invoke-expression', "Dynamic Code Execution (IEX)", "T1059.001"),
            (r'FromBase64String', "Inline Base64 Obfuscation", "T1059.001"),
            (r'wscript(?:\.exe)?', "WScript Shell Host", "T1059.005")
        ]

        found_script_rules = []
        for pattern, label, mitre_id in script_patterns:
            matches = re.findall(pattern, text_content, re.IGNORECASE)
            if matches:
                found_script_rules.append(label)
                mitre_set.add(mitre_id)

        if found_script_rules:
            score += 20
            has_script_syntax = True
            detected_signals.append({
                "rule": "Suspicious_Script_Syntax",
                "category": "Script Execution & Lure Syntax",
                "points": 20,
                "evidence": f"Detected suspicious script patterns: {', '.join(found_script_rules)}"
            })
            mitre_set.add("T1204.002")

        # 4. Host/Network Reconnaissance commands (+15 Points)
        recon_patterns = [
            (r'\bipconfig(?:\s+/all)?\b', "IP Configuration Discovery (ipconfig /all)", "T1082"),
            (r'\bnet\s+view\b', "Network Share Discovery (net view)", "T1083"),
            (r'\btasklist\b', "Process Discovery (tasklist)", "T1057"),
            (r'\bwhoami\b', "User Discovery (whoami)", "T1033"),
            (r'\bsysteminfo\b', "System Info Discovery (systeminfo)", "T1082")
        ]

        found_recon_rules = []
        for pattern, label, mitre_id in recon_patterns:
            if re.search(pattern, text_content, re.IGNORECASE):
                found_recon_rules.append(label)
                mitre_set.add(mitre_id)

        if found_recon_rules:
            score += 15
            has_recon_commands = True
            detected_signals.append({
                "rule": "Host_Network_Reconnaissance",
                "category": "Reconnaissance Commands",
                "points": 15,
                "evidence": f"Detected recon commands: {', '.join(found_recon_rules)}"
            })

        # 5. GTIG LOSTKEYS Keyword / Artifact match (+15 Points)
        if "lostkeys" in text_content.lower():
            score += 15
            detected_signals.append({
                "rule": "LOSTKEYS_Artifact_Keyword",
                "category": "Malware Identifier",
                "points": 15,
                "evidence": "Matched LOSTKEYS malware identifier string in artifact."
            })
            matched_iocs.append({
                "type": "Malware String",
                "value": "LOSTKEYS",
                "description": "Family keyword matching COLDRIVER payload"
            })

        # 6. Multi-Signal Correlation Bonus (+20 Points)
        if has_script_syntax and (has_recon_commands or has_network_iocs):
            score += 20
            detected_signals.append({
                "rule": "Multi_Signal_Correlation_Bonus",
                "category": "Attack Chain Correlation",
                "points": 20,
                "evidence": "CORRELATION ALERT: Suspicious script execution combined with network IoCs/recon commands detected simultaneously!"
            })

        # High Entropy Warning Signal
        if entropy > 5.8:
            detected_signals.append({
                "rule": "High_Shannon_Entropy",
                "category": "Obfuscation Indicator",
                "points": 0,
                "evidence": f"High Shannon entropy calculated ({entropy:.2f} / 8.0), indicating encrypted or Base64 packed payload."
            })

        # Risk Rating Classification:
        # 0–29: LOW, 30–59: MEDIUM, 60–79: HIGH, 80+: CRITICAL
        if score >= 80:
            risk_level = "CRITICAL"
            severity_color = "#FF2A4B"
        elif score >= 60:
            risk_level = "HIGH"
            severity_color = "#FF8C00"
        elif score >= 30:
            risk_level = "MEDIUM"
            severity_color = "#FFD700"
        else:
            risk_level = "LOW"
            severity_color = "#00E676"

        mitre_definitions = {
            "T1059.001": {
                "id": "T1059.001",
                "name": "Command & Scripting Interpreter: PowerShell",
                "tactic": "Execution",
                "description": "Adversaries execute malicious commands or scripts via PowerShell."
            },
            "T1204.002": {
                "id": "T1204.002",
                "name": "User Execution: Malicious Copy-Paste (ClickFix)",
                "tactic": "Execution / Initial Access",
                "description": "Luring victims to copy and execute malicious scripts under the guise of fixing browser/system errors."
            },
            "T1057": {
                "id": "T1057",
                "name": "Process Discovery",
                "tactic": "Discovery",
                "description": "Enumerating running processes using tools like tasklist to identify security software and system state."
            },
            "T1082": {
                "id": "T1082",
                "name": "System Information Discovery",
                "tactic": "Discovery",
                "description": "Gathering detailed system architecture, network interfaces, and IP configurations via ipconfig /all."
            },
            "T1083": {
                "id": "T1083",
                "name": "File and Directory / Network Share Discovery",
                "tactic": "Discovery",
                "description": "Enumerating active domain network shares and system directories using net view."
            },
            "T1059.005": {
                "id": "T1059.005",
                "name": "Command & Scripting Interpreter: Visual Basic / WScript",
                "tactic": "Execution",
                "description": "Executing secondary reconnaissance payloads using Windows Script Host (wscript/cscript)."
            }
        }

        for tid in mitre_set:
            if tid in mitre_definitions:
                mitre_mappings.append(mitre_definitions[tid])

        decoded_payloads = self._extract_base64_payloads(text_content)

        yara_matches = []
        if self.yara_compiled:
            try:
                y_results = self.yara_compiled.match(data=raw_bytes)
                for ym in y_results:
                    yara_matches.append({
                        "rule_name": ym.rule,
                        "meta": ym.meta,
                        "strings": [str(s) for s in ym.strings[:5]]
                    })
            except Exception:
                pass

        return {
            "filename": filename,
            "sha256": file_sha256,
            "entropy": entropy,
            "score": score,
            "risk_level": risk_level,
            "severity_color": severity_color,
            "signals": detected_signals,
            "matched_iocs": matched_iocs,
            "mitre_mappings": mitre_mappings,
            "decoded_payloads": decoded_payloads,
            "yara_matches": yara_matches,
            "engine_mode": "YARA + Regex Engine" if self.yara_compiled else "Regex Defensive Engine (YARA Fallback)"
        }

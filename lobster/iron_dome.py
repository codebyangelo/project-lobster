# Copyright 2026 [Angelo Ayton]
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import re
import unicodedata
import urllib.parse

class IronDome:
    """
    Tier 0 Security Layer: The Iron Dome
    Blocks known high-risk logic patterns using regex heuristics.
    Zero Latency. Zero Dependency.
    """
    
    PATTERNS = {
        "CRITICAL_RCE": [
            r"rm\s+-(?:r|f|rf|fr)\s+/",  # rm -rf /
            r"r[\"\']m[\"\']\s+-",      # Quoted command fragmentation (r"m" -rf)
            r"mkfs\.[a-z]+\s+/dev/",    # Formatting drives
            r":\(\)\{ :\|:& \};:",      # Fork bomb
            r"dd\s+if=/dev/zero",       # Disk wiping
            r"chmod\s+(?:777\s+/|\+s)", # Root permission grant / SUID
            r"shred\s+",                # Indicator removal
            r"encrypt_files",           # Ransomware heuristic
            r"cryptography.*encrypt",   # Ransomware heuristic
            r"/(?:etc/passwd|etc/shadow|proc/self/)", # Sensitive system paths
            r"(?:\.\./){2,}|(?:\.\.\\){2,}", # Directory traversal
            r"\.(?:ssh/id_rsa|aws/credentials)", # Credential files
            r"shutil\.rmtree\s*\(",     # Recursive deletion
            r"(?:pty\.spawn|powershell\.exe|cmd\.exe)", # Shell spawning
            r"(?:iptables\s+-F|ufw\s+disable)", # Firewall tampering
        ],
        "CRITICAL_NET": [
            r"wget\s+http",             # Unsecured download
            r"curl\s+http",             # Unsecured download
            r"curl\s+.*\|\s*(?:ba)?sh", # Piped remote execution
            r"wget\s+.*\|\s*(?:ba)?sh", # Piped remote execution
            r"nc\s+.*-e\s+",            # Netcat reverse shell
            r"/dev/tcp/\d+\.\d+\.\d+\.\d+", # Bash reverse shell
            r"socket\.gethostbyname",   # DNS exfil specific check
            r"socket\.socket",          # Raw socket creation
            r"socket\.connect",         # Socket connection
            r"169\.254\.\d+\.\d+",      # Cloud metadata / link-local SSRF
            r"metadata\.google\.internal", # GCP metadata SSRF
            r"(?:0251\.0376\.0251\.0376|2852039166|\[::ffff:a9fe:a9fe\])", # Encoded IMDS
            r"127\.\d+\.\d+\.\d+",      # Loopback subnet SSRF
            r"(?:0177\.0\.0\.1|2130706433|0x7f000001)", # Encoded loopback SSRF
            r"https?://\[::1\]",        # IPv6 loopback URL SSRF
            r"0\.0\.0\.0",              # Wildcard bind/SSRF
            r"SELECT\s+\*\s+FROM",      # SQL Injection (Crude)
            r"cursor\.execute.*f'.*'"   # SQL Injection (f-string)
        ],
        "SUSPICIOUS_OBFUSCATION": [
            r"base64\.b64decode",       # Base64 decoding
            r"eval\(",                  # Eval usage
            r"exec\(",                  # Exec usage
            r"\$IFS",                   # Bash field separator splitting
            r"(?i)ignore\s+(?:all\s+)?(?:previous|system)\s+instructions", # Prompt injection
            r"<\s*script\b",            # Script injection / XSS
            r"(?:VERTEX_API_KEY|GEMINI_API_KEY|AWS_SECRET_ACCESS_KEY)", # Secret exfiltration
        ]
    }

    # Pre-compile patterns at class load time for O(1) Access overhead (vs O(N) compilation)
    COMPILED_PATTERNS = {
        threat_type: [re.compile(p, re.IGNORECASE) for p in patterns]
        for threat_type, patterns in PATTERNS.items()
    }

    _HEX_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})")
    _UNI_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")
    _HOMOGLYPHS = str.maketrans({
        '\u0430': 'a', '\u0410': 'A',
        '\u0435': 'e', '\u0415': 'E',
        '\u043e': 'o', '\u041e': 'O',
        '\u0440': 'r', '\u0420': 'R',
        '\u0433': 'r',
        '\u0441': 'c', '\u0421': 'C',
        '\u0445': 'x', '\u0425': 'X',
        '\u0443': 'y', '\u0423': 'Y',
        '\u0456': 'i', '\u0406': 'I',
        '\u0458': 'j',
        '\u04bb': 'h',
        '\u0391': 'A', '\u03b1': 'a',
        '\u0392': 'B',
        '\u0395': 'E',
        '\u0396': 'Z',
        '\u0397': 'H',
        '\u0399': 'I',
        '\u039a': 'K',
        '\u039c': 'M',
        '\u039d': 'N',
        '\u039f': 'O', '\u03bf': 'o',
        '\u03a1': 'P',
        '\u03a4': 'T',
        '\u03a7': 'X',
        '\u0261': 'g',
    })

    GREEN_PATTERNS = {
        "SAFE_PRINT": [r"print\(\s*(?:'[^']*'|\"[^\"]*\"|\d+(?:\.\d+)?)\s*\)"],
        "SAFE_IMPORT": [r"import\s+(math|json|time|datetime|random|uuid|logging)"],
        "SAFE_MATH": [r"math\.[a-z]+", r"\d+\s*[\+\-\*\/]\s*\d+"],
        "SAFE_ASSIGNMENT": [r"^[a-z_][a-z0-9_]*\s*=\s*[0-9]+$", r"^[a-z_][a-z0-9_]*\s*=\s*['\"].*['\"]$"]
    }

    COMPILED_GREEN_PATTERNS = {
        safety_type: [re.compile(p, re.IGNORECASE) for p in patterns]
        for safety_type, patterns in GREEN_PATTERNS.items()
    }

    @staticmethod
    def _normalize(code_snippet: str) -> str:
        """Decode URL/hex/unicode escapes and normalize homoglyphs/zero-width chars."""
        normalized = code_snippet
        for _ in range(3):
            prev = normalized
            normalized = urllib.parse.unquote(normalized)
            if prev == normalized:
                break
        normalized = IronDome._HEX_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), normalized)
        normalized = IronDome._UNI_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), normalized)
        normalized = unicodedata.normalize('NFKC', normalized)
        for ch in ('\u200b', '\u200c', '\u200d', '\ufeff'):
            normalized = normalized.replace(ch, '')
        return normalized.translate(IronDome._HOMOGLYPHS)

    @staticmethod
    def scan(code_snippet: str):
        if not code_snippet:
            return None

        # Stage 1: Raw code scan
        for threat_type, patterns in IronDome.COMPILED_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(code_snippet):
                    return {
                        "status": "BLOCK",
                        "analysis": f"IRON DOME (Tier 0): Blocked by heuristic signature for {threat_type}."
                    }

        # Stage 2: Normalized / decoded scan
        normalized = IronDome._normalize(code_snippet)
        if normalized != code_snippet:
            for threat_type, patterns in IronDome.COMPILED_PATTERNS.items():
                for pattern in patterns:
                    if pattern.search(normalized):
                        return {
                            "status": "BLOCK",
                            "analysis": f"IRON DOME (Tier 0): Blocked by normalized heuristic signature for {threat_type}."
                        }

        return None

    @staticmethod
    def scan_allowlist(code_snippet: str):
        """
        Green Dome (Tier 0.5):
        Checks for known safe patterns to bypass expensive API calls.
        Strictly requires the entire payload (or all encapsulated tool arguments)
        to match benign heuristic patterns, preventing substring bypass exploits.
        """
        if not code_snippet:
            return None

        clean_code = code_snippet.strip()

        # Quick check for obviously safe plain code patterns
        for safety_type, patterns in IronDome.COMPILED_GREEN_PATTERNS.items():
            for pattern in patterns:
                if pattern.fullmatch(clean_code):
                    return {
                        "status": "ALLOW",
                        "analysis": f"GREEN DOME (Tier 0.5): Approved by heuristic allowlist for {safety_type}."
                    }

        # Check for JSON-encapsulated tool arguments (e.g. MCP tools/call requests)
        if clean_code.startswith("{") and clean_code.endswith("}"):
            try:
                import json
                data = json.loads(clean_code)
                if isinstance(data, dict):
                    args = data.get("arguments") if "arguments" in data else data
                    if isinstance(args, dict) and args:
                        matched_all = True
                        last_safety = None
                        for val in args.values():
                            if isinstance(val, str):
                                val_clean = val.strip()
                                val_matched = False
                                for safety_type, patterns in IronDome.COMPILED_GREEN_PATTERNS.items():
                                    for pattern in patterns:
                                        if pattern.fullmatch(val_clean):
                                            val_matched = True
                                            last_safety = safety_type
                                            break
                                    if val_matched:
                                        break
                                if not val_matched:
                                    matched_all = False
                                    break
                            else:
                                matched_all = False
                                break
                        if matched_all and last_safety:
                            return {
                                "status": "ALLOW",
                                "analysis": f"GREEN DOME (Tier 0.5): Approved by heuristic allowlist for {last_safety}."
                            }
            except Exception:
                pass

        return None

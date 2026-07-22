from __future__ import annotations

import re
from dataclasses import dataclass

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: str
    confidence: float
    summary: str
    regex: re.Pattern[str]
    capability: str


SECRET_PATTERNS = [
    ("aws-credentials", "AWS credentials", re.compile(r"\.aws[/'\"]\s*(,\s*)?['\"]?(credentials|config)|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY", re.I)),
    ("ssh-private-key", "SSH private keys", re.compile(r"\.ssh/(id_rsa|id_ed25519|config)|BEGIN OPENSSH PRIVATE KEY", re.I)),
    ("gcp-credentials", "Google Cloud credentials", re.compile(r"application_default_credentials|GOOGLE_APPLICATION_CREDENTIALS", re.I)),
    ("npm-token", "npm tokens", re.compile(r"\.npmrc|NPM_TOKEN|:_authToken", re.I)),
    ("github-token", "GitHub tokens", re.compile(r"GITHUB_TOKEN|ghp_[A-Za-z0-9_]{20,}|github\.com/settings/tokens", re.I)),
    ("env-file", "environment files", re.compile(r"""(?:['"/`]|readfilesync\s*\(\s*['"`])\.env(?:\.[a-z]+)?['"`]|process\.env\.[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API|AUTH)[A-Z0-9_]*""", re.I)),
]

CODE_RULES = [
    # Do not match bare exec()/spawn(): in JavaScript those are commonly
    # RegExp.prototype.exec() and application-level event methods.  A capability
    # finding needs an identifiable OS-process API, not a name collision.
    Rule("process-execution", "execution", "LOW", 0.54, "Extension can spawn local processes. Common for language servers and debuggers.", re.compile(r"(?:\b(?:child_process|cp)\s*\.\s*(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\(|require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\)\s*\.\s*(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\(|\b(?:execSync|execFile|execFileSync|spawnSync)\s*\(|\bProcessBuilder\b|Runtime\.getRuntime\(\)\.exec)"), "process_execution"),
    Rule("network-access", "network", "LOW", 0.48, "Extension performs network requests. Not malicious by itself.", re.compile(r"\b(fetch\(|axios\.|https?\.request|XMLHttpRequest|WebSocket|request\.write|req\.write|OkHttpClient|HttpClient|URLConnection)"), "network"),
    Rule("filesystem-access", "filesystem", "LOW", 0.42, "Extension reads or writes local files. Expected for many developer tools.", re.compile(r"\b(fs\.(readFile|readFileSync|writeFile|readdir|createReadStream|createWriteStream)|workspace\.fs|FileInputStream|FileOutputStream)"), "filesystem"),
    Rule("dynamic-code-loading", "code", "MEDIUM", 0.66, "Extension uses dynamic code loading or evaluation.", re.compile(r"\b(eval\(|new Function\(|vm\.runIn|import\s*\(|URLClassLoader|ClassLoader\.defineClass)"), "dynamic_code"),
    Rule("obfuscation", "code", "LOW", 0.46, "Extension contains obfuscation indicators.", re.compile(r"(atob\(|Buffer\.from\([^)]*,\s*['\"]base64['\"]|(?:\\x[0-9a-fA-F]{2}){4,}|[A-Za-z0-9+/]{220,}={0,2})"), "obfuscation"),
    Rule("destructive-file-pattern", "filesystem", "MEDIUM", 0.76, "Extension contains recursive or forceful destructive file operation patterns.", re.compile(r"\b(rm\s+-rf|rmSync\([^)]*recursive\s*:\s*true)\b"), "destructive_file_activity"),
]

FILE_READ_RE = re.compile(r"\b(fs\.(readFile|readFileSync|createReadStream)|workspace\.fs\.readFile|FileInputStream|readText|readBytes)\b")
FILE_WRITE_RE = re.compile(r"\b(fs\.(writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream)|workspace\.fs\.writeFile|FileOutputStream|writeText|writeBytes)\b")
NETWORK_SINK_RE = re.compile(r"\b(?:fetch\s*\(|axios\.(?:post|put|request)\s*\(|https?\.request\s*\(|XMLHttpRequest\b|WebSocket\b|request\.write\s*\(|req\.write\s*\(|OkHttpClient\b|HttpClient\b|URLConnection\b)")
ENCODE_ARCHIVE_RE = re.compile(r"\b(Buffer\.from|btoa\(|atob\(|base64|createGzip|archiver|adm-zip|JSZip|zip\b|createCipheriv|crypto\.publicEncrypt)\b", re.I)
DESTRUCTIVE_RE = re.compile(r"\b(rm\s+-rf|rmSync\([^)]*recursive\s*:\s*true)\b")
DOWNLOAD_RE = re.compile(
    r"(?:\bfetch\s*\(|\bhttps?\.(?:get|request)\b|\baxios\.get\b|\bcurl\s+|\bwget\s+)"
)


def score_finding(severity: str, confidence: float) -> int:
    base = {"INFO": 5, "LOW": 20, "MEDIUM": 45, "HIGH": 78, "CRITICAL": 95}.get(severity, 0)
    return min(100, round(base * confidence + base * 0.22))


def rank_severity(left: str, right: str) -> str:
    return right if SEVERITY_ORDER[right] > SEVERITY_ORDER[left] else left

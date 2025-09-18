#!/usr/bin/env python3
"""
🚀 CyberStrike AI — All-in-One Security Scanner for Your Website
- Enter your URL and get a comprehensive security assessment
- AI-enhanced vulnerability detection with false positive reduction
- Directory scanning, port scanning, and domain intelligence
- Generates detailed JSON and executive summary reports
"""

import asyncio
import aiohttp
import json
import os
import re
import sys
import time
import hashlib
import socket
import threading
import requests
from urllib.parse import urlparse, urljoin, parse_qsl, urlencode, urlunparse
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, asdict
from datetime import datetime
import dns.resolver

# AI Integration
try:
    import google.generativeai as genai
    GOOGLE_AI_AVAILABLE = True
except ImportError:
    print("Warning: google-generativeai not available. AI features disabled.")
    GOOGLE_AI_AVAILABLE = False

# Color support
try:
    from colorama import Fore, init
    init(autoreset=True)
    COLOR_SUPPORT = True
except ImportError:
    COLOR_SUPPORT = False
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = RESET = ""

# -------------------------
# Configuration & Globals
# -------------------------

@dataclass
class AIVulnerabilityFinding:
    url: str
    method: str
    injected_param: str
    payload: str
    vulnerability_type: str
    severity: str
    confidence: float
    detection_source: str
    ai_analysis: Optional[Dict[str, str]]
    response_status: int
    response_length: int
    response_time: float

class Config:
    DEFAULT_USER_AGENT = "CyberStrike-AI/1.0"
    DEFAULT_CONCURRENCY = 15
    DEFAULT_TIMEOUT = 15
    DEFAULT_DELAY = 0.3
    REPORT_JSON = "cyberstrike_report.json"
    EXECUTIVE_SUMMARY = "executive_summary.txt"
    _seen_payloads: Set[str] = set()

# -------------------------
# Severity & Remediation
# -------------------------

SEVERITY_MAP = {
    "sql_injection": ("HIGH", "Use parameterized queries. Never concatenate user input into SQL."),
    "xss": ("HIGH", "Encode output and implement CSP headers."),
    "command_injection": ("CRITICAL", "Never pass user input to system shells. Use safe APIs."),
    "path_traversal": ("HIGH", "Validate file paths. Use a whitelist of allowed characters."),
    "template_injection": ("HIGH", "Avoid evaluating user input in templates. Use sandboxed engines."),
    "ldap_injection": ("MEDIUM", "Use LDAP libraries with parameterized queries."),
    "xxe": ("HIGH", "Disable external entities in XML parsers."),
    "ssrf": ("MEDIUM", "Validate and sanitize URLs. Restrict to allowed domains."),
    "error_disclosure": ("LOW", "Show generic error pages. Never expose stack traces."),
    "timing_attack": ("MEDIUM", "Use constant-time comparisons. Add response jitter."),
    "business_logic": ("MEDIUM", "Review edge cases and implement proper access controls."),
    "auth_bypass": ("CRITICAL", "Validate authentication on every request."),
    "reflection": ("LOW", "Sanitize and encode user input before output."),
    "server_error": ("MEDIUM", "Implement proper exception handling."),
    "header_disclosure": ("LOW", "Remove sensitive headers like Server, X-Powered-By."),
    "open_redirect": ("MEDIUM", "Validate redirect URLs. Use a whitelist of allowed domains."),
    "clickjacking": ("MEDIUM", "Implement X-Frame-Options header or Content Security Policy."),
    "cors_misconfig": ("MEDIUM", "Restrict Access-Control-Allow-Origin to specific trusted domains."),
    "host_header_injection": ("MEDIUM", "Validate Host header. Use server-side configuration for domain validation."),
    "directory_listing": ("LOW", "Disable directory listing in web server configuration."),
    "information_disclosure": ("LOW", "Remove sensitive information from responses and headers."),
}

# -------------------------
# Payload Management
# -------------------------

def load_payloads() -> List[str]:
    """Load default payloads for vulnerability scanning"""
    default_payloads = [
        # SQL Injection
        "' OR '1'='1",
        "' OR 1=1--",
        "\" OR \"\"=\"",
        "'; WAITFOR DELAY '0:0:5'--",
        "admin'--",
        # XSS
        "<script>alert(1)</script>",
        "\"><script>alert(document.cookie)</script>",
        "javascript:alert(1)",
        "<img src=x onerror=alert(1)>",
        # Command Injection
        "; whoami",
        "| whoami",
        "`whoami`",
        "$(whoami)",
        # Path Traversal
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "/etc/passwd",
        # Template Injection
        "{{7*7}}",
        "${7*7}",
        # LDAP Injection
        "*)(&)",
        "*)(uid=*))(|(uid=*",
        # XXE
        '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>',
        # Open Redirect
        "https://evil.com",
        "//evil.com",
        # SSRF
        "http://169.254.169.254",
        "http://localhost:8080",
    ]
    
    # Create payloads file if it doesn't exist
    if not os.path.exists("payloads.txt"):
        with open("payloads.txt", "w") as f:
            for p in default_payloads:
                f.write(p + "\n")
        print(f"{Fore.YELLOW}[*] Created payloads.txt with default payloads.{Fore.RESET}")

    # Also return the default payloads for immediate use
    return default_payloads

def safe_filter_payloads(payloads: List[str], aggressive: bool = False) -> List[str]:
    """Filter out potentially destructive payloads unless in aggressive mode"""
    if aggressive:
        return payloads

    destructive = [
        r"\bDROP\s+(DATABASE|TABLE)\b", r"\bDELETE\s+FROM\b", r"\bUPDATE\s+\w+\s+SET\b",
        r"\bSHUTDOWN\b", r"rm\s+-rf", r";\s*shutdown", r"/bin/bash", r"cmd\.exe"
    ]
    
    return [p for p in payloads if not any(re.search(pat, p, re.IGNORECASE) for pat in destructive)]

def is_duplicate_payload(payload: str) -> bool:
    """Simple duplicate detection"""
    h = hashlib.md5(payload.encode()).hexdigest()
    if h in Config._seen_payloads:
        return True
    Config._seen_payloads.add(h)
    return False

# -------------------------
# AI Analysis Engine
# -------------------------

class AIVulnerabilityAnalyzer:
    def __init__(self, api_key: str):
        if not GOOGLE_AI_AVAILABLE:
            raise RuntimeError("Google Generative AI not available.")
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-pro')
        self._cache = {}

    def _create_ai_prompt(self, finding: Dict[str, Any], resp_text: str, headers: Dict[str, str]) -> str:
        return f"""
        You are a senior cybersecurity analyst. Analyze this web scan result.
        Respond ONLY with valid JSON in this exact format:
        {{
            "is_vulnerable": true/false,
            "vulnerability_type": "string",
            "confidence_score": 0.0-1.0,
            "explanation": "string",
            "technical_details": "string",
            "exploitation_difficulty": "easy/medium/hard",
            "remediation": "string"
        }}

        Data:
        URL: {finding.get('url', 'N/A')}
        Method: {finding.get('method', 'N/A')}
        Parameter: {finding.get('injected_param', 'N/A')}
        Payload: {finding.get('payload', 'N/A')}
        Status: {finding.get('status', 'N/A')}
        Response Snippet: {resp_text[:800]}...
        Headers: {json.dumps(headers)}
        """

    async def analyze(self, finding: Dict[str, Any], resp_text: str, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
        cache_key = f"{finding.get('url', '')}_{finding.get('payload', '')}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        prompt = self._create_ai_prompt(finding, resp_text, headers)
        
        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None, 
                lambda: self.model.generate_content(prompt)
            )
            
            if not response or not response.text:
                return None

            json_match = re.search(r'```json\s*([\s\S]*?)\s*```', response.text)
            json_text = json_match.group(1) if json_match else response.text
            ai_result = json.loads(json_text)
            self._cache[cache_key] = ai_result
            return ai_result

        except Exception as e:
            print(f"{Fore.RED}[AI] Error: {str(e)[:100]}...{Fore.RESET}")
            return None

# -------------------------
# Detection Engine
# -------------------------

SQL_ERROR_SIGNS = ["sql syntax", "sql error", "mysql", "syntax error", "native client", "odbc", "unterminated", "pdoexception", "sqlstate", "postgresql", "sqlite", "ora-", "oracle", "pl/sql", "sql server"]
XSS_SIGNS = ["<script>", "alert(", "onerror=", "onload=", "javascript:", "eval(", "document.cookie", "document.location", "window.location", "String.fromCharCode"]
COMMAND_INJECTION_SIGNS = ["; whoami", "| whoami", "& whoami", "`whoami`", "$(whoami)", "&& whoami", "|| whoami", "; ls", "| ls", "& ls"]

def analyze_response_traditional(orig_payload: str, resp_text: str, status: int, headers: Dict[str, str], rtime: float) -> List[Dict[str, Any]]:
    """Performs initial, rule-based vulnerability detection."""
    findings = []
    lowtext = resp_text.lower()

    # Check for reflected XSS
    if orig_payload and orig_payload in resp_text:
        findings.append({"type": "reflection", "confidence": 0.3, "detail": "Payload reflected", "source": "pattern_match"})

    # Check for SQL errors
    for sig in SQL_ERROR_SIGNS:
        if sig in lowtext:
            findings.append({"type": "sql_injection", "confidence": 0.7, "detail": f"SQL error: {sig}", "source": "pattern_match"})
            break

    # Check for XSS indicators
    for sig in XSS_SIGNS:
        if sig.lower() in lowtext:
            findings.append({"type": "xss", "confidence": 0.6, "detail": f"XSS pattern: {sig}", "source": "pattern_match"})
            break

    # Check for server errors
    if status >= 500:
        findings.append({"type": "server_error", "confidence": 0.4, "detail": f"HTTP {status}", "source": "pattern_match"})

    # Check for information disclosure in headers
    disclosure_headers = [f"{h}: {headers[h]}" for h in ["server", "x-powered-by", "x-aspnet-version"] if h in headers]
    if disclosure_headers:
        findings.append({"type": "header_disclosure", "confidence": 0.2, "detail": "; ".join(disclosure_headers), "source": "pattern_match"})

    # Check for timing anomalies (potential blind injection)
    if rtime > 8.0:
        findings.append({"type": "timing_attack", "confidence": 0.5, "detail": f"Slow response: {rtime:.2f}s", "source": "timing_analysis"})

    return findings

# -------------------------
# Core Scanner
# -------------------------

class CyberStrikeScanner:
    def __init__(self, session: aiohttp.ClientSession, ai_analyzer: Optional[AIVulnerabilityAnalyzer], concurrency: int, delay: float):
        self.session = session
        self.ai_analyzer = ai_analyzer
        self.semaphore = asyncio.Semaphore(concurrency)
        self.delay = delay
        self.report: List[AIVulnerabilityFinding] = []
        self._stats = {"total_requests": 0, "ai_verified": 0, "pattern_only": 0, "false_positives_reduced": 0}
        self.directory_findings = []
        self.port_scan_results = []
        self.domain_intel = {}

    def _map_to_finding(self, base: Dict[str, Any], ai_result: Optional[Dict[str, Any]]) -> Optional[AIVulnerabilityFinding]:
        if not ai_result or not ai_result.get("is_vulnerable", False):
            return None

        vuln_type = ai_result.get("vulnerability_type", base.get("type", "unknown"))
        severity, remediation = SEVERITY_MAP.get(vuln_type, ("MEDIUM", "No remediation advice."))

        return AIVulnerabilityFinding(
            url=base["url"], method=base["method"], injected_param=base["injected_param"], payload=base["payload"],
            vulnerability_type=vuln_type, severity=severity, confidence=ai_result.get("confidence_score", 0.5),
            detection_source="ai_analysis",
            ai_analysis={
                "explanation": ai_result.get("explanation", "No explanation."),
                "technical_details": ai_result.get("technical_details", "No details."),
                "exploitation_difficulty": ai_result.get("exploitation_difficulty", "unknown"),
                "remediation": ai_result.get("remediation", remediation)
            },
            response_status=base.get("status", 0), response_length=base.get("length", 0), response_time=base.get("rtime", 0.0)
        )

    async def probe_get(self, url: str, payload: str, param: str, timeout: int):
        parsed = urlparse(url)
        qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
        qs[param] = payload
        test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

        async with self.semaphore:
            if self.delay > 0: 
                await asyncio.sleep(self.delay)
            start = time.monotonic()
            try:
                async with self.session.get(test_url, timeout=timeout) as r:
                    text = await r.text(errors="ignore")
                    await self._analyze_response(r, "GET", test_url, payload, param, start, text)
            except Exception:
                pass

    async def probe_post(self, url: str, payload: str, param: str, base_data: Dict[str, Any], timeout: int):
        data = base_data.copy()
        data[param] = payload
        async with self.semaphore:
            if self.delay > 0: 
                await asyncio.sleep(self.delay)
            start = time.monotonic()
            try:
                async with self.session.post(url, data=data, timeout=timeout) as r:
                    text = await r.text(errors="ignore")
                    await self._analyze_response(r, "POST", url, payload, param, start, text, data)
            except Exception:
                pass

    async def _analyze_response(self, response, method: str, url: str, payload: str, param: str, start_time: float, text: str, post_data: Optional[Dict[str, Any]] = None):
        rtime = time.monotonic() - start_time
        findings = analyze_response_traditional(payload, text, response.status, dict(response.headers), rtime)

        for fd in findings:
            self._stats["total_requests"] += 1
            base_finding = {
                "url": url, 
                "method": method, 
                "injected_param": param, 
                "payload": payload, 
                "status": response.status, 
                "length": len(text), 
                "rtime": rtime, 
                **fd
            }
            enhanced = None

            if self.ai_analyzer:
                ai_res = await self.ai_analyzer.analyze(base_finding, text, dict(response.headers))
                if ai_res:
                    enhanced = self._map_to_finding(base_finding, ai_res)
                    if enhanced: 
                        self._stats["ai_verified"] += 1
                    else: 
                        self._stats["false_positives_reduced"] += 1

            if not enhanced:
                vuln_type = fd["type"]
                severity, remediation = SEVERITY_MAP.get(vuln_type, ("LOW", "No advice"))
                enhanced = AIVulnerabilityFinding(
                    url=url, 
                    method=method, 
                    injected_param=param, 
                    payload=payload, 
                    vulnerability_type=vuln_type,
                    severity=severity, 
                    confidence=fd["confidence"], 
                    detection_source=fd["source"], 
                    ai_analysis=None,
                    response_status=response.status, 
                    response_length=len(text), 
                    response_time=rtime
                )
                self._stats["pattern_only"] += 1

            if enhanced:
                self.report.append(enhanced)

    async def run_vulnerability_scan(self, url: str, payloads: List[str], timeout: int, methods: List[str]):
        """Run vulnerability scan on a target URL"""
        parsed = urlparse(url)
        qs_keys = list(dict(parse_qsl(parsed.query, keep_blank_values=True)).keys())
        param_names = qs_keys or ['q', 'id', 'search', 's', 'term', 'query']
        tasks = []

        for payload in payloads:
            if is_duplicate_payload(payload):
                continue
            if "GET" in methods:
                for param in param_names:
                    tasks.append(self.probe_get(url, payload, param, timeout))
            if "POST" in methods:
                base_data = {p: "" for p in param_names}
                for param in param_names:
                    tasks.append(self.probe_post(url, payload, param, base_data, timeout))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def run_directory_scan(self, base_url: str):
        """Scan for common directories and files"""
        print(f"{Fore.CYAN}🔍 Starting directory scan on: {base_url}{Fore.RESET}")
        
        # Common directory wordlist
        wordlist = [
            "admin", "login", "wp-admin", "dashboard", "api", "uploads", "backup", 
            "config", "phpmyadmin", "cpanel", "webmail", "cgi-bin", "robots.txt",
            ".git", ".env", "composer.json", "package.json", "README.md", "LICENSE",
            "wp-login.php", "administrator", "user", "users", "account", "accounts",
            "auth", "authentication", "signin", "signup", "register", "wp-content",
            "includes", "inc", "lib", "libs", "vendor", "node_modules", "database",
            "db", "sql", "data", "files", "filemanager", "manager", "console",
            "test", "tests", "dev", "development", "staging", "prod", "production"
        ]
        
        extensions = ["", ".php", ".html", ".bak", ".zip", "/", ".txt", ".json", ".old", ".sql"]
        
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
        ]
        
        risky_keywords = ["admin", "login", "panel", "config", "phpmyadmin", "cpanel", "shell", "upload", "dashboard", "backup", "wp-admin", "wp-login"]
        
        for word in wordlist:
            for ext in extensions:
                full_url = urljoin(base_url.rstrip("/") + "/", word + ext)
                headers = {'User-Agent': user_agents[0]}
                try:
                    res = requests.get(full_url, headers=headers, timeout=4, allow_redirects=False)
                    code = res.status_code
                    if code in [200, 301, 302, 403]:
                        color = {
                            200: Fore.GREEN,
                            301: Fore.CYAN,
                            302: Fore.CYAN,
                            403: Fore.YELLOW
                        }.get(code, Fore.RESET)

                        line = f"[{code}] {full_url}"
                        print(color + line + Fore.RESET)

                        self.directory_findings.append({
                            "url": full_url,
                            "status_code": code,
                            "is_risky": any(risk in full_url.lower() for risk in risky_keywords)
                        })
                        
                except requests.RequestException:
                    pass

    def run_port_scan(self, target: str):
        """Scan common ports on target"""
        print(f"{Fore.CYAN}📡 Starting port scan on: {target}{Fore.RESET}")
        
        # Common web-related ports to scan
        common_ports = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 5432, 8080, 8443, 8000, 9000, 9090]
        
        open_ports = []
        
        def scan_port(target_ip, port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    open_ports.append(port)
                    print(f"{Fore.GREEN}🔓 Port {port} is OPEN{Fore.RESET}")
                sock.close()
            except:
                pass

        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            print(f"{Fore.RED}❌ Could not resolve target: {target}{Fore.RESET}")
            return

        threads = []
        for port in common_ports:
            t = threading.Thread(target=scan_port, args=(target_ip, port))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self.port_scan_results = open_ports
        if not open_ports:
            print(f"{Fore.GREEN}✅ No common web ports found open.{Fore.RESET}")
        else:
            print(f"{Fore.GREEN}✅ Open ports: {open_ports}{Fore.RESET}")

    def gather_domain_intelligence(self, url: str):
        """Gather domain intelligence"""
        print(f"{Fore.CYAN}🧠 Gathering domain intelligence for: {url}{Fore.RESET}")
        
        parsed = urlparse(url)
        domain = parsed.netloc
        
        intel = {
            "domain": domain,
            "ip_address": None,
            "ssl_info": None,
            "hosting_provider": "Unknown",
            "dns_records": {},
            "whois_info": None,
            "risk_indicators": {}
        }
        
        # Get IP address
        try:
            intel["ip_address"] = socket.gethostbyname(domain)
        except:
            pass
            
        # Get SSL info (if HTTPS)
        if parsed.scheme == 'https':
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        intel["ssl_info"] = cert.get('notAfter') if cert else None
            except:
                pass
                
        # Get hosting provider
        if intel["ip_address"]:
            try:
                response = requests.get(f"https://ipinfo.io/{intel['ip_address']}/json", timeout=5)
                if response.status_code == 200:
                    intel["hosting_provider"] = response.json().get('org', 'Unknown')
            except:
                pass
                
        # Get DNS records
        record_types = ['A', 'MX', 'NS', 'TXT']
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                intel["dns_records"][rtype] = [r.to_text() for r in answers]
            except:
                intel["dns_records"][rtype] = []
                
        # Risk indicators
        intel["risk_indicators"] = {
            "suspicious_url": any(k in url.lower() for k in ['login', 'secure', 'verify', 'update', 'bonus', 'win', 'bank', 'signin', 'paypal']),
            "ip_based": bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain)),
            "no_https": parsed.scheme != 'https'
        }
        
        self.domain_intel = intel
        
        # Print summary
        print(f"{Fore.BLUE}🌐 IP Address: {intel['ip_address'] or 'Unknown'}{Fore.RESET}")
        if intel["ssl_info"]:
            print(f"{Fore.BLUE}🔐 SSL Certificate: Valid until {intel['ssl_info']}{Fore.RESET}")
        print(f"{Fore.BLUE}🏢 Hosting Provider: {intel['hosting_provider']}{Fore.RESET}")
        print(f"{Fore.BLUE}⚠️  Risk Indicators: {sum(intel['risk_indicators'].values())} found{Fore.RESET}")

    def get_statistics(self) -> Dict[str, Any]:
        """Returns scan statistics for reporting."""
        total_vulns = len(self.report)
        ai_discovered = sum(1 for f in self.report if f.detection_source == "ai_analysis")
        high_confidence = sum(1 for f in self.report if f.confidence >= 0.8)
        directory_findings = len(self.directory_findings)
        risky_directories = sum(1 for f in self.directory_findings if f["is_risky"])
        open_ports = len(self.port_scan_results)
        
        # Calculate a simple risk score
        severity_weights = {"LOW": 1, "MEDIUM": 3, "HIGH": 7, "CRITICAL": 10}
        risk_score = sum(severity_weights.get(f.severity, 1) * f.confidence for f in self.report)
        risk_score += risky_directories * 2  # Add weight for risky directories
        risk_score += open_ports * 1.5  # Add weight for open ports
        
        return {
            "total_vulnerabilities": total_vulns,
            "ai_discovered": ai_discovered,
            "pattern_discovered": total_vulns - ai_discovered,
            "high_confidence": high_confidence,
            "directory_findings": directory_findings,
            "risky_directories": risky_directories,
            "open_ports": open_ports,
            "risk_score": round(risk_score, 2),
            **self._stats
        }

# -------------------------
# Reporting
# -------------------------

def save_json_report(scanner: CyberStrikeScanner, stats: Dict[str, Any], json_path: str = Config.REPORT_JSON):
    """Saves a comprehensive JSON report."""
    report_data = {
        "scan_summary": {
            "vulnerability_summary": stats,
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S")
        },
        "domain_intelligence": scanner.domain_intel,
        "directory_findings": scanner.directory_findings,
        "port_scan_results": scanner.port_scan_results,
        "detailed_vulnerabilities": [asdict(f) for f in scanner.report]
    }
    
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
    
    print(f"{Fore.GREEN}✅ JSON report saved: {json_path}{Fore.RESET}")

def save_executive_summary(scanner: CyberStrikeScanner, stats: Dict[str, Any], txt_path: str = Config.EXECUTIVE_SUMMARY):
    """Saves a human-readable executive summary."""
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("=== CYBERSTRIKE AI - COMPREHENSIVE SECURITY REPORT ===\n\n")
        f.write(f"Scan Completed: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Overall Risk Score: {stats['risk_score']}\n\n")
        
        f.write("=== VULNERABILITY SUMMARY ===\n")
        f.write(f"Total Vulnerabilities: {stats['total_vulnerabilities']}\n")
        f.write(f"AI Verified Findings: {stats['ai_discovered']}\n")
        f.write(f"High Confidence Findings: {stats['high_confidence']}\n\n")
        
        f.write("=== ADDITIONAL FINDINGS ===\n")
        f.write(f"Directory Findings: {stats['directory_findings']}\n")
        f.write(f"Risky Directories: {stats['risky_directories']}\n")
        f.write(f"Open Ports: {stats['open_ports']}\n\n")
        
        if scanner.report:
            f.write("=== DETAILED VULNERABILITIES ===\n\n")
            for i, finding in enumerate(scanner.report, 1):
                f.write(f"--- Finding #{i} ---\n")
                f.write(f"URL: {finding.url}\n")
                f.write(f"Type: {finding.vulnerability_type}\n")
                f.write(f"Severity: {finding.severity}\n")
                f.write(f"Confidence: {finding.confidence:.2f}\n")
                f.write(f"Source: {finding.detection_source}\n")
                if finding.ai_analysis:
                    f.write(f"Remediation: {finding.ai_analysis['remediation']}\n")
                f.write("\n")
        
        if scanner.directory_findings:
            f.write("=== DIRECTORY FINDINGS ===\n\n")
            for finding in scanner.directory_findings:
                if finding["is_risky"]:
                    f.write(f"⚠️  [RISKY] {finding['url']} (Status: {finding['status_code']})\n")
                else:
                    f.write(f"✅ {finding['url']} (Status: {finding['status_code']})\n")
            f.write("\n")
            
        if scanner.port_scan_results:
            f.write("=== OPEN PORTS ===\n")
            f.write(f"{', '.join(map(str, scanner.port_scan_results))}\n\n")
    
    print(f"{Fore.GREEN}✅ Executive summary saved: {txt_path}{Fore.RESET}")

def print_summary(stats: Dict[str, Any]):
    """Prints a summary to the console."""
    print(f"\n{Fore.MAGENTA}" + "="*60)
    print(f"{Fore.CYAN}📊 CYBERSTRIKE AI SCAN COMPLETE")
    print(f"{Fore.MAGENTA}" + "="*60 + f"{Fore.RESET}")
    print(f"{Fore.GREEN}Total Vulnerabilities:   {stats['total_vulnerabilities']}{Fore.RESET}")
    print(f"{Fore.BLUE}AI Verified:            {stats['ai_discovered']}{Fore.RESET}")
    print(f"{Fore.YELLOW}Risky Directories:      {stats['risky_directories']}{Fore.RESET}")
    print(f"{Fore.CYAN}Open Ports:             {stats['open_ports']}{Fore.RESET}")
    print(f"{Fore.RED}Overall Risk Score:     {stats['risk_score']}{Fore.RESET}")
    print(f"{Fore.MAGENTA}" + "="*60 + f"{Fore.RESET}")

# -------------------------
# Main Execution
# -------------------------

async def main():
    # Prompt user for target URL
    print(f"{Fore.CYAN}🚀 Welcome to CyberStrike AI - All-in-One Security Scanner{Fore.RESET}")
    print(f"{Fore.YELLOW}Enter the URL of the website you want to scan:{Fore.RESET}")
    
    target_url = input(f"{Fore.GREEN}URL: {Fore.RESET}").strip()
    
    # Validate and normalize URL
    if not target_url:
        print(f"{Fore.RED}❌ No URL provided. Exiting.{Fore.RESET}")
        return
        
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    # Parse URL to validate
    try:
        parsed = urlparse(target_url)
        if not parsed.netloc:
            print(f"{Fore.RED}❌ Invalid URL format. Please enter a valid URL (e.g., https://your-website.com){Fore.RESET}")
            return
    except Exception:
        print(f"{Fore.RED}❌ Invalid URL format. Please enter a valid URL.{Fore.RESET}")
        return
    
    print(f"{Fore.CYAN}🎯 Target URL: {target_url}{Fore.RESET}")
    
    # Load payloads
    payloads = load_payloads()
    payloads = safe_filter_payloads(payloads)
    if not payloads:
        print(f"{Fore.RED}[!] No payloads available. Exiting.{Fore.RESET}")
        return

    # Initialize AI (if API key available)
    ai_analyzer = None
    gemini_key = os.getenv('GEMINI_API_KEY')
    if gemini_key and GOOGLE_AI_AVAILABLE:
        try:
            ai_analyzer = AIVulnerabilityAnalyzer(gemini_key)
            print(f"{Fore.GREEN}🤖 Google Gemini AI initialized{Fore.RESET}")
        except Exception as e:
            print(f"{Fore.RED}[!] AI init failed: {e}{Fore.RESET}")

    # Start scanning
    timeout_obj = aiohttp.ClientTimeout(total=Config.DEFAULT_TIMEOUT)
    connector = aiohttp.TCPConnector(limit_per_host=Config.DEFAULT_CONCURRENCY)
    
    async with aiohttp.ClientSession(timeout=timeout_obj, connector=connector, headers={"User-Agent": Config.DEFAULT_USER_AGENT}) as session:
        print(f"\n{Fore.CYAN}🚀 Starting comprehensive security scan...{Fore.RESET}")
        print(f"{Fore.CYAN}{'='*50}{Fore.RESET}")
        
        # Create scanner instance
        scanner = CyberStrikeScanner(session, ai_analyzer, Config.DEFAULT_CONCURRENCY, Config.DEFAULT_DELAY)
        
        # 1. Gather domain intelligence
        scanner.gather_domain_intelligence(target_url)
        
        # 2. Run port scan
        parsed_target = urlparse(target_url)
        domain = parsed_target.netloc
        scanner.run_port_scan(domain)
        
        # 3. Run directory scan
        scanner.run_directory_scan(target_url)
        
        # 4. Run vulnerability scan
        print(f"{Fore.CYAN}🔍 Starting vulnerability scan on: {target_url}{Fore.RESET}")
        await scanner.run_vulnerability_scan(target_url, payloads, Config.DEFAULT_TIMEOUT, ["GET", "POST"])
        
        # Generate reports
        stats = scanner.get_statistics()
        domain_name = domain.replace(".", "_")
        save_json_report(scanner, stats, f"{domain_name}_report.json")
        save_executive_summary(scanner, stats, f"{domain_name}_summary.txt")
        
        # Print summary
        print_summary(stats)
        
        print(f"\n{Fore.GREEN}🎉 Scan completed successfully!{Fore.RESET}")
        print(f"{Fore.YELLOW}Reports saved as:")
        print(f"  • {domain_name}_report.json")
        print(f"  • {domain_name}_summary.txt{Fore.RESET}")

if __name__ == "__main__":
    # Import random here to avoid issues
    import random
    import ssl
    
    # Run the main function
    asyncio.run(main())
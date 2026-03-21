"""
Module VulnScan Pro : os_fingerprint
Identifie le système d'exploitation de la cible via l'analyse du TTL (64=Linux, 128=Windows),
les en-têtes Server, X-Powered-By et d'autres indicateurs HTTP.

AVERTISSEMENT : À utiliser uniquement sur des cibles autorisées.
"""
import sys
import json
import argparse
import time
import re
import subprocess
import platform
from urllib.parse import urlparse
import requests

sys.path.insert(0, '..')
from core.base_module import BaseModule


OS_REFS = [
    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
    "https://cwe.mitre.org/data/definitions/200.html",
    "https://nmap.org/book/osdetect.html",
]

TTL_OS_MAP = {
    (1,   64):  "Linux/Unix",
    (65, 128):  "Windows",
    (129, 255): "Network Device (Cisco/Juniper)",
}

SERVER_OS_HINTS = {
    "ubuntu":   "Linux (Ubuntu)",
    "debian":   "Linux (Debian)",
    "centos":   "Linux (CentOS)",
    "fedora":   "Linux (Fedora)",
    "red hat":  "Linux (Red Hat)",
    "rhel":     "Linux (RHEL)",
    "suse":     "Linux (SUSE)",
    "alpine":   "Linux (Alpine)",
    "win":      "Windows Server",
    "iis":      "Windows Server (IIS)",
    "microsoft":"Windows Server",
    "freebsd":  "FreeBSD",
    "openbsd":  "OpenBSD",
    "unix":     "Unix",
}

POWERED_BY_OS = {
    "asp.net":  "Windows / .NET",
    "php":      "Linux/Windows (PHP)",
    "rails":    "Linux (Ruby on Rails)",
    "express":  "Linux/Node.js",
    "django":   "Linux (Python/Django)",
    "tomcat":   "Linux/Windows (Java)",
    "jboss":    "Linux/Windows (JBoss)",
    "weblogic": "Linux/Windows (WebLogic)",
}


class Module(BaseModule):

    def _ping_ttl(self, host: str, timeout: int) -> int | None:
        """Get TTL from ping response."""
        try:
            is_windows = platform.system().lower() == "windows"
            if is_windows:
                cmd = ["ping", "-n", "1", "-w", "2000", host]
            else:
                cmd = ["ping", "-c", "1", "-W", "2", host]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            m = re.search(r"ttl=(\d+)", result.stdout, re.IGNORECASE)
            if m:
                return int(m.group(1))
        except Exception:
            pass
        return None

    def run(self, url: str, depth: str = "normal", timeout: int = 30) -> dict:
        start = time.time()
        vulns = []
        req_timeout = min(timeout, 8)

        try:
            parsed = urlparse(url)
            host = parsed.hostname or parsed.netloc.split(":")[0]

            os_hints = []
            evidence = {}

            # 1. HTTP headers analysis
            try:
                resp = requests.get(url, timeout=req_timeout, verify=False,
                                    headers={"User-Agent": "VulnScan-Pro/1.0"})
                server = resp.headers.get("Server", "")
                x_powered = resp.headers.get("X-Powered-By", "")
                x_aspnet = resp.headers.get("X-AspNet-Version", "")
                x_aspnetmvc = resp.headers.get("X-AspNetMvc-Version", "")

                if server:
                    evidence["Server"] = server
                    server_lower = server.lower()
                    for kw, os_name in SERVER_OS_HINTS.items():
                        if kw in server_lower:
                            os_hints.append(os_name)
                            break

                if x_powered:
                    evidence["X-Powered-By"] = x_powered
                    xp_lower = x_powered.lower()
                    for kw, tech in POWERED_BY_OS.items():
                        if kw in xp_lower:
                            os_hints.append(tech)
                            break

                if x_aspnet:
                    evidence["X-AspNet-Version"] = x_aspnet
                    os_hints.append(f"Windows / .NET {x_aspnet}")

                if x_aspnetmvc:
                    evidence["X-AspNetMvc-Version"] = x_aspnetmvc

                # Check for Windows-specific paths in error pages
                if "\\\\windows\\" in resp.text.lower() or "c:\\\\inetpub" in resp.text.lower():
                    os_hints.append("Windows (chemin Windows dans la réponse)")
                    evidence["body_hint"] = "Chemin Windows détecté"

            except requests.exceptions.RequestException as e:
                pass

            # 2. TTL-based OS fingerprinting
            ttl = self._ping_ttl(host, min(timeout // 2, 10))
            if ttl:
                evidence["TTL"] = ttl
                for (low, high), os_name in TTL_OS_MAP.items():
                    if low <= ttl <= high:
                        os_hints.append(f"{os_name} (TTL={ttl})")
                        break

            if os_hints or evidence:
                os_summary = ", ".join(set(os_hints)) if os_hints else "Inconnu"
                evidence_str = "; ".join(f"{k}: {v}" for k, v in evidence.items())
                vulns.append(self.vuln(
                    name=f"Système d'exploitation identifié : {os_summary}",
                    severity="LOW",
                    cvss_score=3.7,
                    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    cwe_id="CWE-200",
                    endpoint=url,
                    description=(
                        f"Le système d'exploitation de la cible a été identifié : {os_summary}. "
                        f"Indicateurs : {evidence_str}. "
                        "Ces informations permettent à un attaquant de cibler des vulnérabilités "
                        "et des exploits spécifiques à l'OS."
                    ),
                    impact="Fingerprinting OS permettant le ciblage d'exploits kernel et service spécifiques.",
                    evidence=f"OS identifié via : {evidence_str}.",
                    recommendation=(
                        "Supprimer les en-têtes révélateurs (Server, X-Powered-By, X-AspNet-Version). "
                        "Apache : ServerTokens Prod. Nginx : server_tokens off. "
                        "PHP : expose_php = Off. ASP.NET : supprimer X-AspNet-Version dans web.config. "
                        "Maintenir l'OS à jour avec les derniers patches de sécurité."
                    ),
                    references=OS_REFS,
                ))

        except Exception as e:
            duration = int((time.time() - start) * 1000)
            return self.error("os_fingerprint", str(e), duration)

        duration = int((time.time() - start) * 1000)
        return self.result("os_fingerprint", vulns, duration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScan Pro — OS Fingerprinting")
    parser.add_argument("--url",     required=True,        help="URL cible")
    parser.add_argument("--depth",   default="normal",     help="Profondeur du scan")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout en secondes")
    args = parser.parse_args()

    module = Module()
    result = module.run(args.url, args.depth, args.timeout)
    print(json.dumps(result, ensure_ascii=False))

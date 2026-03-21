"""
Module VulnScan Pro : service_version_scan
Récupère les versions des services exposés et interroge l'API NVD (NIST)
pour identifier les CVEs connus associés à ces versions.

AVERTISSEMENT : À utiliser uniquement sur des cibles autorisées.
"""
import sys
import json
import argparse
import time
import re
import socket
from urllib.parse import urlparse
import requests

sys.path.insert(0, '..')
from core.base_module import BaseModule


SERVICE_REFS = [
    "https://nvd.nist.gov/vuln/search",
    "https://cve.mitre.org/",
    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration",
    "https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html",
]

VERSION_PATTERNS = [
    (r"Apache[/ ](\d+\.\d+\.\d+)", "Apache HTTP Server"),
    (r"nginx[/ ](\d+\.\d+\.\d+)", "nginx"),
    (r"OpenSSH[_\-](\d+\.\d+p?\d*)", "OpenSSH"),
    (r"Microsoft-IIS[/ ](\d+\.\d+)", "Microsoft IIS"),
    (r"PHP[/ ](\d+\.\d+\.\d+)", "PHP"),
    (r"MySQL.*?(\d+\.\d+\.\d+)", "MySQL"),
    (r"PostgreSQL.*?(\d+\.\d+)", "PostgreSQL"),
    (r"Redis server v=(\d+\.\d+\.\d+)", "Redis"),
    (r"ProFTPD (\d+\.\d+\.\d+)", "ProFTPD"),
    (r"vsftpd (\d+\.\d+\.\d+)", "vsftpd"),
    (r"Exim (\d+\.\d+)", "Exim"),
    (r"lighttpd[/ ](\d+\.\d+\.\d+)", "lighttpd"),
    (r"Python[/ ](\d+\.\d+\.\d+)", "Python"),
    (r"Ruby[/ ](\d+\.\d+\.\d+)", "Ruby"),
    (r"Node\.js[/ ]v?(\d+\.\d+\.\d+)", "Node.js"),
    (r"Tomcat[/ ](\d+\.\d+\.\d+)", "Apache Tomcat"),
]

PROBE_PORTS = {
    21:    (b"", "FTP"),
    22:    (b"", "SSH"),
    25:    (b"EHLO vulnscan\r\n", "SMTP"),
    80:    (b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n", "HTTP"),
    3306:  (b"", "MySQL"),
    5432:  (b"", "PostgreSQL"),
    6379:  (b"INFO server\r\n", "Redis"),
    8080:  (b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n", "HTTP-alt"),
}


class Module(BaseModule):

    def _grab_banner(self, host: str, port: int, probe: bytes, timeout: float) -> str:
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                s.settimeout(timeout)
                if probe:
                    s.sendall(probe)
                return s.recv(512).decode("utf-8", errors="ignore")
        except Exception:
            return ""

    def _query_nvd(self, keyword: str, version: str) -> list:
        """Query NVD API for CVEs matching keyword+version."""
        try:
            resp = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={
                    "keywordSearch": f"{keyword} {version}",
                    "resultsPerPage": 5,
                },
                timeout=10,
                headers={"User-Agent": "VulnScan-Pro/1.0"},
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
            cves = []
            for item in data.get("vulnerabilities", [])[:5]:
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "")
                descriptions = cve_data.get("descriptions", [])
                desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
                metrics = cve_data.get("metrics", {})
                cvss_score = None
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics and metrics[key]:
                        cvss_score = metrics[key][0].get("cvssData", {}).get("baseScore")
                        break
                if cve_id:
                    cves.append({"id": cve_id, "desc": desc[:200], "cvss": cvss_score})
            return cves
        except Exception:
            return []

    def run(self, url: str, depth: str = "normal", timeout: int = 30) -> dict:
        start = time.time()
        vulns = []
        req_timeout = min(timeout, 5)

        try:
            parsed = urlparse(url)
            host = parsed.hostname or parsed.netloc.split(":")[0]

            detected_services = {}

            # 1. HTTP headers — most reliable
            try:
                resp = requests.get(
                    url,
                    timeout=req_timeout,
                    verify=False,
                    headers={"User-Agent": "VulnScan-Pro/1.0"},
                )
                header_text = " ".join([
                    resp.headers.get("Server", ""),
                    resp.headers.get("X-Powered-By", ""),
                    resp.headers.get("X-AspNet-Version", ""),
                ])
                for pattern, service_name in VERSION_PATTERNS:
                    m = re.search(pattern, header_text, re.IGNORECASE)
                    if m:
                        detected_services[service_name] = m.group(1)
            except Exception:
                pass

            # 2. Banner grabbing on ports
            if depth != "fast":
                for port, (probe, proto) in PROBE_PORTS.items():
                    if (time.time() - start) > timeout * 0.6:
                        break
                    banner = self._grab_banner(host, port, probe, 2.5)
                    if not banner:
                        continue
                    for pattern, service_name in VERSION_PATTERNS:
                        m = re.search(pattern, banner, re.IGNORECASE)
                        if m and service_name not in detected_services:
                            detected_services[service_name] = m.group(1)

            # 3. Query NVD for each detected service
            for service_name, version in detected_services.items():
                if (time.time() - start) > timeout * 0.85:
                    break
                cves = self._query_nvd(service_name, version) if depth != "fast" else []

                if cves:
                    top_cve = cves[0]
                    cvss = top_cve.get("cvss") or 7.5
                    severity = "CRITICAL" if cvss >= 9.0 else "HIGH" if cvss >= 7.0 else "MEDIUM"
                    cve_list = ", ".join(c["id"] for c in cves)
                    vulns.append(self.vuln(
                        name=f"{service_name} {version} — CVEs connus détectés",
                        severity=severity,
                        cvss_score=float(cvss),
                        endpoint=url,
                        cve_id=cves[0]["id"],
                        description=(
                            f"{service_name} version {version} est exposé. "
                            f"{len(cves)} CVE(s) connu(s) pour cette version : {cve_list}. "
                            f"CVE le plus sévère : {top_cve['id']} (CVSS {cvss}) — {top_cve['desc'][:150]}"
                        ),
                        recommendation=(
                            f"Mettre à jour {service_name} vers la dernière version stable. "
                            "Masquer les informations de version dans les en-têtes et banners. "
                            "S'abonner aux alertes CVE pour les logiciels utilisés. "
                            "Appliquer les patches de sécurité dès publication."
                        ),
                        references=SERVICE_REFS + [f"https://nvd.nist.gov/vuln/detail/{cves[0]['id']}"],
                    ))
                else:
                    # Service version detected but no CVEs found (or fast mode)
                    vulns.append(self.vuln(
                        name=f"Version de service exposée : {service_name} {version}",
                        severity="HIGH",
                        cvss_score=7.5,
                        endpoint=url,
                        description=(
                            f"{service_name} version {version} est exposé dans les en-têtes/banners. "
                            "La divulgation de version permet à un attaquant de rechercher "
                            "des exploits spécifiques à cette version."
                        ),
                        recommendation=(
                            f"Masquer la version de {service_name}. "
                            "Maintenir le service à jour. "
                            "Vérifier les CVEs sur https://nvd.nist.gov/"
                        ),
                        references=SERVICE_REFS,
                    ))

        except Exception as e:
            duration = int((time.time() - start) * 1000)
            return self.error("service_version_scan", str(e), duration)

        duration = int((time.time() - start) * 1000)
        return self.result("service_version_scan", vulns, duration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScan Pro — Service Version Scanner")
    parser.add_argument("--url",     required=True,        help="URL cible")
    parser.add_argument("--depth",   default="normal",     help="Profondeur du scan")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout en secondes")
    args = parser.parse_args()

    module = Module()
    result = module.run(args.url, args.depth, args.timeout)
    print(json.dumps(result, ensure_ascii=False))

"""
Module VulnScan Pro : firewall_detection
Détecte la présence d'un WAF/pare-feu via les en-têtes de réponse
(X-Sucuri-ID, CF-RAY, X-Powered-By-Plesk, etc.) et le comportement du serveur.

AVERTISSEMENT : À utiliser uniquement sur des cibles autorisées.
"""
import sys
import json
import argparse
import time
import re
from urllib.parse import urlparse
import requests

sys.path.insert(0, '..')
from core.base_module import BaseModule


WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["CF-RAY", "cf-ray", "CF-Cache-Status"],
        "cookies": ["__cfduid", "cf_clearance"],
        "body_patterns": [r"cloudflare", r"Attention Required", r"Ray ID:"],
        "server": ["cloudflare"],
    },
    "AWS WAF / CloudFront": {
        "headers": ["X-Cache", "X-Amz-Cf-Id", "X-Amzn-RequestId"],
        "cookies": [],
        "body_patterns": [r"Request blocked", r"AWS", r"CloudFront"],
        "server": ["CloudFront"],
    },
    "Sucuri": {
        "headers": ["X-Sucuri-ID", "X-Sucuri-Cache"],
        "cookies": [],
        "body_patterns": [r"Sucuri", r"Access Denied - Sucuri"],
        "server": ["Sucuri/Cloudproxy"],
    },
    "Imperva / Incapsula": {
        "headers": ["X-Iinfo", "X-CDN"],
        "cookies": ["incap_ses", "visid_incap"],
        "body_patterns": [r"Incapsula", r"Imperva"],
        "server": ["Imperva"],
    },
    "Akamai": {
        "headers": ["X-Check-Cacheable", "X-Akamai-Transformed"],
        "cookies": ["ak_bmsc"],
        "body_patterns": [r"Reference #\d+\.\w+"],
        "server": ["AkamaiGHost"],
    },
    "F5 BIG-IP ASM": {
        "headers": ["X-Cnection", "Set-Cookie"],
        "cookies": ["TS0", "BIGipServer"],
        "body_patterns": [r"The requested URL was rejected", r"F5"],
        "server": ["BigIP"],
    },
    "Plesk / cPanel WAF": {
        "headers": ["X-Powered-By-Plesk"],
        "cookies": [],
        "body_patterns": [],
        "server": ["Plesk"],
    },
    "ModSecurity": {
        "headers": ["X-Content-Type-Options"],
        "cookies": [],
        "body_patterns": [r"ModSecurity", r"mod_security", r"Not Acceptable"],
        "server": ["mod_security"],
    },
    "Barracuda": {
        "headers": ["X-Barracuda-Connect", "X-Barracuda-Start-Time"],
        "cookies": ["barra_counter_session"],
        "body_patterns": [r"Barracuda"],
        "server": [],
    },
    "Fortinet FortiGate": {
        "headers": [],
        "cookies": ["cookiesession1"],
        "body_patterns": [r"FortiGate", r"Fortigate"],
        "server": [],
    },
}

FIREWALL_REFS = [
    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/08-Test_RIA_Cross_Domain_Policy",
    "https://www.sans.org/blog/identifying-web-application-firewalls/",
    "https://github.com/EnableSecurity/wafw00f",
]


class Module(BaseModule):

    def run(self, url: str, depth: str = "normal", timeout: int = 30) -> dict:
        start = time.time()
        vulns = []
        req_timeout = min(timeout, 10)

        try:
            session = requests.Session()
            session.headers["User-Agent"] = "VulnScan-Pro/1.0"

            # 1. Normal request
            try:
                resp = session.get(url, timeout=req_timeout, allow_redirects=True)
            except requests.exceptions.RequestException as e:
                return self.error("firewall_detection", str(e), 0)

            headers = {k.lower(): v for k, v in resp.headers.items()}
            cookies = {c.name.lower(): c.value for c in session.cookies}
            body = resp.text[:2000]

            detected_wafs = []

            for waf_name, sigs in WAF_SIGNATURES.items():
                found = False
                # Check headers
                for h in sigs["headers"]:
                    if h.lower() in headers:
                        found = True
                        break
                # Check cookies
                if not found:
                    for c in sigs["cookies"]:
                        if c.lower() in cookies:
                            found = True
                            break
                # Check body patterns
                if not found:
                    for pattern in sigs["body_patterns"]:
                        if re.search(pattern, body, re.IGNORECASE):
                            found = True
                            break
                # Check Server header
                if not found:
                    server_val = headers.get("server", "")
                    for s in sigs.get("server", []):
                        if s.lower() in server_val.lower():
                            found = True
                            break

                if found:
                    detected_wafs.append(waf_name)

            # 2. Send a malicious payload to trigger WAF (if not blocked on first req)
            if depth != "fast":
                try:
                    malicious_url = f"{url}?id=1' OR 1=1--&cmd=<script>alert(1)</script>"
                    waf_resp = session.get(malicious_url, timeout=req_timeout, allow_redirects=True)
                    if waf_resp.status_code in (403, 406, 419, 429, 503):
                        if "Cloudflare" not in detected_wafs:
                            detected_wafs.append("WAF générique (blocage payload détecté)")
                    elif waf_resp.status_code == resp.status_code:
                        # Same response = WAF not triggered = potential bypass risk
                        vulns.append(self.vuln(
                            name="Aucun WAF/IPS détecté — payloads malicieux non bloqués",
                            severity="MEDIUM",
                            cvss_score=4.0,
                            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                            cwe_id="CWE-693",
                            endpoint=url,
                            description=(
                                "Aucun WAF ni système de prévention d'intrusion n'a été détecté. "
                                "Des payloads malicieux (SQLi, XSS) ont été envoyés sans déclencher "
                                "de blocage. L'application est exposée sans protection périmétrique."
                            ),
                            impact="Exploitation directe des vulnérabilités applicatives sans blocage périmétrique.",
                            evidence="Payload SQLi+XSS envoyé sans déclencher HTTP 403/429/503.",
                            recommendation=(
                                "Déployer un Web Application Firewall (WAF) en frontal. "
                                "Solutions cloud : Cloudflare, AWS WAF, Imperva. "
                                "Solutions open-source : ModSecurity avec règles OWASP CRS. "
                                "Configurer des règles IPS sur le réseau."
                            ),
                            references=FIREWALL_REFS,
                        ))
                except requests.exceptions.RequestException:
                    pass

            if detected_wafs:
                waf_list = ", ".join(detected_wafs)
                vulns.append(self.vuln(
                    name=f"WAF/Firewall détecté : {waf_list}",
                    severity="MEDIUM",
                    cvss_score=4.0,
                    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    cwe_id="CWE-200",
                    endpoint=url,
                    description=(
                        f"Un ou plusieurs WAF/firewalls ont été identifiés : {waf_list}. "
                        "La présence d'un WAF est une information de reconnaissance importante. "
                        "Les WAF peuvent être contournés avec des techniques d'obfuscation avancées."
                    ),
                    impact="Information de reconnaissance, possibilité de contournement WAF ciblé.",
                    evidence=f"Signatures WAF détectées via en-têtes/cookies/corps de réponse : {waf_list}.",
                    recommendation=(
                        "Les WAF ne remplacent pas un code sécurisé. "
                        "Combiner WAF avec des pratiques de développement sécurisé. "
                        "Mettre à jour régulièrement les règles WAF. "
                        "Tester régulièrement les règles WAF avec des pentests."
                    ),
                    references=FIREWALL_REFS,
                ))

        except Exception as e:
            duration = int((time.time() - start) * 1000)
            return self.error("firewall_detection", str(e), duration)

        duration = int((time.time() - start) * 1000)
        return self.result("firewall_detection", vulns, duration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScan Pro — Firewall/WAF Detection")
    parser.add_argument("--url",     required=True,        help="URL cible")
    parser.add_argument("--depth",   default="normal",     help="Profondeur du scan")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout en secondes")
    args = parser.parse_args()

    module = Module()
    result = module.run(args.url, args.depth, args.timeout)
    print(json.dumps(result, ensure_ascii=False))

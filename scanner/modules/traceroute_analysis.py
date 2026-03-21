"""
Module VulnScan Pro : traceroute_analysis
Effectue un traceroute vers la cible pour analyser le chemin réseau,
compter les hops et détecter des informations d'infrastructure.

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

sys.path.insert(0, '..')
from core.base_module import BaseModule


TRACEROUTE_REFS = [
    "https://www.iana.org/assignments/service-names-port-numbers/",
    "https://www.sans.org/white-papers/33",
    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/",
]


class Module(BaseModule):

    def run(self, url: str, depth: str = "normal", timeout: int = 30) -> dict:
        start = time.time()
        vulns = []
        req_timeout = min(timeout, 25)

        try:
            parsed = urlparse(url)
            host = parsed.hostname or parsed.netloc.split(":")[0]

            # Determine OS and traceroute command
            is_windows = platform.system().lower() == "windows"
            max_hops = 15 if depth == "fast" else 20

            if is_windows:
                cmd = ["tracert", "-d", "-w", "2000", "-h", str(max_hops), host]
            else:
                cmd = ["traceroute", "-n", "-w", "2", "-m", str(max_hops), host]

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=req_timeout,
                )
                output = result.stdout + result.stderr
            except subprocess.TimeoutExpired:
                output = ""
            except FileNotFoundError:
                # traceroute not available — try using ping to count TTL
                output = ""
                try:
                    ping_cmd = ["ping", "-c", "3", "-t", "64", host] if not is_windows else ["ping", "-n", "3", host]
                    ping_result = subprocess.run(ping_cmd, capture_output=True, text=True, timeout=10)
                    output = ping_result.stdout
                except Exception:
                    pass

            if not output:
                duration = int((time.time() - start) * 1000)
                return self.result("traceroute_analysis", [], duration)

            # Parse hop count
            hop_count = 0
            ip_pattern = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")
            hops_ips = ip_pattern.findall(output)
            lines = output.splitlines()
            for line in lines:
                m = re.match(r"^\s*(\d+)\s", line)
                if m:
                    hop_count = max(hop_count, int(m.group(1)))

            # Count timeouts (*)
            timeout_count = output.count("* * *") + output.count("*  *  *")

            # Detect private network hops
            private_hops = []
            for ip in set(hops_ips):
                parts = ip.split(".")
                if len(parts) == 4:
                    first, second = int(parts[0]), int(parts[1])
                    if (first == 10 or
                        (first == 172 and 16 <= second <= 31) or
                        (first == 192 and second == 168)):
                        private_hops.append(ip)

            # Report findings
            if hop_count > 0:
                vulns.append(self.vuln(
                    name=f"Analyse réseau : {hop_count} hops vers la cible",
                    severity="LOW",
                    cvss_score=3.0,
                    cvss_vector="AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    cwe_id="CWE-200",
                    endpoint=host,
                    description=(
                        f"Le traceroute vers '{host}' a révélé {hop_count} saut(s) réseau. "
                        f"{f'Des adresses IP privées ont été détectées dans le chemin : {chr(44).join(private_hops[:3])}. ' if private_hops else ''}"
                        f"{f'{timeout_count} hop(s) ont refusé de répondre (firewall/ACL). ' if timeout_count > 3 else ''}"
                        "Ces informations permettent de cartographier l'infrastructure réseau."
                    ),
                    impact="Cartographie réseau facilitée, identification des équipements intermédiaires.",
                    evidence=f"Traceroute vers '{host}' : {hop_count} hops détectés.",
                    recommendation=(
                        "Configurer les équipements réseau pour ne pas répondre aux paquets ICMP TTL-Exceeded. "
                        "Filtrer les réponses ICMP aux seuls équipements nécessaires. "
                        "Utiliser un réseau privé virtuel (VPN) pour les communications sensibles."
                    ),
                    references=TRACEROUTE_REFS,
                ))

            if private_hops:
                vulns.append(self.vuln(
                    name="Adresses IP privées exposées dans le chemin réseau",
                    severity="LOW",
                    cvss_score=3.0,
                    cvss_vector="AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    cwe_id="CWE-200",
                    endpoint=host,
                    description=(
                        f"Des adresses IP privées (RFC1918) ont été révélées dans le traceroute : "
                        f"{', '.join(set(private_hops)[:5])}. "
                        "Cela expose la topologie du réseau interne."
                    ),
                    impact="Exposition de la topologie réseau interne, facilite les attaques ciblées.",
                    evidence=f"IPs privées RFC1918 visibles dans le traceroute : {', '.join(set(private_hops)[:5])}.",
                    recommendation=(
                        "Configurer le NAT pour masquer les adresses internes. "
                        "Désactiver les réponses ICMP TTL-Exceeded sur les équipements internes. "
                        "Revoir la politique de filtrage ICMP."
                    ),
                    references=TRACEROUTE_REFS,
                ))

        except Exception as e:
            duration = int((time.time() - start) * 1000)
            return self.error("traceroute_analysis", str(e), duration)

        duration = int((time.time() - start) * 1000)
        return self.result("traceroute_analysis", vulns, duration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScan Pro — Traceroute Analysis")
    parser.add_argument("--url",     required=True,        help="URL cible")
    parser.add_argument("--depth",   default="normal",     help="Profondeur du scan")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout en secondes")
    args = parser.parse_args()

    module = Module()
    result = module.run(args.url, args.depth, args.timeout)
    print(json.dumps(result, ensure_ascii=False))

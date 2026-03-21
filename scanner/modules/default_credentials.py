"""
Module VulnScan Pro : default_credentials
Teste les identifiants par défaut (admin/admin, root/root, admin/password)
sur l'authentification HTTP Basic et les formulaires de login détectés.

AVERTISSEMENT : À utiliser uniquement sur des cibles autorisées.
"""
import sys
import json
import argparse
import time
import re
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup

sys.path.insert(0, '..')
from core.base_module import BaseModule


DEFAULT_CREDS = [
    ("admin",     "admin"),
    ("admin",     "password"),
    ("admin",     "12345"),
    ("admin",     "123456"),
    ("admin",     "1234567890"),
    ("admin",     ""),
    ("root",      "root"),
    ("root",      "toor"),
    ("root",      ""),
    ("root",      "password"),
    ("user",      "user"),
    ("user",      "password"),
    ("test",      "test"),
    ("guest",     "guest"),
    ("demo",      "demo"),
    ("operator",  "operator"),
    ("manager",   "manager"),
    ("support",   "support"),
    ("service",   "service"),
]

LOGIN_PATHS = [
    "/login", "/signin", "/admin", "/admin/login",
    "/user/login", "/wp-login.php", "/wp-admin",
    "/phpmyadmin", "/pma", "/administrator",
    "/manager", "/console", "/portal",
]

SUCCESS_INDICATORS = [
    r"dashboard", r"logout", r"sign out", r"profile", r"welcome",
    r"mon compte", r"tableau de bord", r"déconnexion",
    r"successfully", r"bienvenue",
]

FAIL_INDICATORS = [
    r"invalid", r"incorrect", r"wrong", r"fail", r"error",
    r"bad credentials", r"unauthorized", r"forbidden",
    r"identifiant incorrect", r"mot de passe incorrect",
]

DEFAULT_CREDS_REFS = [
    "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
    "https://cwe.mitre.org/data/definitions/798.html",
    "https://cwe.mitre.org/data/definitions/521.html",
    "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
]

SUCCESS_RE = re.compile("|".join(SUCCESS_INDICATORS), re.IGNORECASE)
FAIL_RE    = re.compile("|".join(FAIL_INDICATORS),    re.IGNORECASE)


class Module(BaseModule):

    def _test_basic_auth(self, url: str, username: str, password: str, timeout: float) -> bool:
        """Test HTTP Basic Auth credentials."""
        try:
            resp = requests.get(url, auth=(username, password), timeout=timeout,
                                headers={"User-Agent": "VulnScan-Pro/1.0"})
            return resp.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def _find_login_form(self, url: str, session: requests.Session, timeout: float) -> dict | None:
        """Parse login form from page."""
        try:
            resp = session.get(url, timeout=timeout, allow_redirects=True)
            if resp.status_code not in (200, 401):
                return None
            soup = BeautifulSoup(resp.text, "html.parser")
            forms = soup.find_all("form")
            for form in forms:
                inputs = form.find_all("input")
                user_field = pass_field = None
                for inp in inputs:
                    t = (inp.get("type", "text") or "text").lower()
                    n = (inp.get("name", "") or "").lower()
                    if t == "password" or "pass" in n:
                        pass_field = inp.get("name")
                    elif t in ("text", "email") or "user" in n or "email" in n or "login" in n:
                        user_field = inp.get("name")
                if user_field and pass_field:
                    action = form.get("action", url)
                    method = form.get("method", "post").upper()
                    ep = action if action.startswith("http") else f"{urlparse(url).scheme}://{urlparse(url).netloc}{action}"
                    hidden = {i.get("name"): i.get("value", "")
                              for i in inputs
                              if i.get("type", "").lower() == "hidden" and i.get("name")}
                    return {
                        "endpoint": ep,
                        "method":   method,
                        "user_field": user_field,
                        "pass_field": pass_field,
                        "hidden": hidden,
                    }
        except Exception:
            pass
        return None

    def _test_form_login(self, form: dict, username: str, password: str,
                         session: requests.Session, timeout: float) -> bool:
        """Submit login form with given credentials."""
        try:
            data = {**form["hidden"], form["user_field"]: username, form["pass_field"]: password}
            if form["method"] == "POST":
                resp = session.post(form["endpoint"], data=data, timeout=timeout, allow_redirects=True)
            else:
                resp = session.get(form["endpoint"], params=data, timeout=timeout, allow_redirects=True)
            text = resp.text.lower()
            if resp.status_code in (302, 303):
                return True
            if SUCCESS_RE.search(text) and not FAIL_RE.search(text):
                return True
            return False
        except requests.exceptions.RequestException:
            return False

    def run(self, url: str, depth: str = "normal", timeout: int = 30) -> dict:
        start = time.time()
        vulns = []
        req_timeout = min(timeout, 6)

        try:
            session = requests.Session()
            session.headers["User-Agent"] = "VulnScan-Pro/1.0"
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # 1. HTTP Basic Auth test on target URL
            try:
                probe = session.get(url, timeout=req_timeout)
                if probe.status_code == 401 and "Basic" in probe.headers.get("WWW-Authenticate", ""):
                    for username, password in DEFAULT_CREDS[:8]:
                        if (time.time() - start) > timeout * 0.3:
                            break
                        if self._test_basic_auth(url, username, password, req_timeout):
                            creds_str = f"{username}/{password if password else '(vide)'}"
                            vulns.append(self.vuln(
                                name=f"Identifiants par défaut acceptés (HTTP Basic Auth) : {creds_str}",
                                severity="CRITICAL",
                                cvss_score=9.8,
                                endpoint=url,
                                payload=creds_str,
                                description=(
                                    f"L'authentification HTTP Basic sur '{url}' accepte "
                                    f"les identifiants par défaut '{creds_str}'. "
                                    "Un attaquant peut accéder immédiatement à l'interface protégée."
                                ),
                                recommendation=(
                                    "Changer immédiatement les identifiants par défaut. "
                                    "Utiliser des mots de passe forts et uniques. "
                                    "Implémenter MFA. "
                                    "Préférer JWT/OAuth2 à HTTP Basic Auth."
                                ),
                                references=DEFAULT_CREDS_REFS,
                            ))
                            break
            except Exception:
                pass

            # 2. Find and test login forms
            login_paths = [url] + [f"{base_url}{p}" for p in LOGIN_PATHS[:6 if depth == "fast" else len(LOGIN_PATHS)]]
            form_found = None

            for path in login_paths:
                if (time.time() - start) > timeout * 0.4:
                    break
                form = self._find_login_form(path, session, req_timeout)
                if form:
                    form_found = form
                    break

            if form_found:
                creds_to_test = DEFAULT_CREDS[:5] if depth == "fast" else DEFAULT_CREDS
                for username, password in creds_to_test:
                    if (time.time() - start) > timeout * 0.85:
                        break
                    success = self._test_form_login(form_found, username, password, session, req_timeout)
                    if success:
                        creds_str = f"{username}/{password if password else '(vide)'}"
                        vulns.append(self.vuln(
                            name=f"Identifiants par défaut acceptés (formulaire) : {creds_str}",
                            severity="CRITICAL",
                            cvss_score=9.8,
                            endpoint=form_found["endpoint"],
                            payload=creds_str,
                            description=(
                                f"Le formulaire de connexion sur '{form_found['endpoint']}' "
                                f"accepte les identifiants par défaut '{creds_str}'. "
                                "L'application est compromise par des credentials triviaux."
                            ),
                            recommendation=(
                                "Forcer le changement du mot de passe au premier démarrage. "
                                "Implémenter une politique de mots de passe forts. "
                                "Utiliser MFA pour les accès administratifs. "
                                "Surveiller les tentatives d'authentification."
                            ),
                            references=DEFAULT_CREDS_REFS,
                        ))
                        break

        except Exception as e:
            duration = int((time.time() - start) * 1000)
            return self.error("default_credentials", str(e), duration)

        duration = int((time.time() - start) * 1000)
        return self.result("default_credentials", vulns, duration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScan Pro — Default Credentials Tester")
    parser.add_argument("--url",     required=True,        help="URL cible")
    parser.add_argument("--depth",   default="normal",     help="Profondeur du scan")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout en secondes")
    args = parser.parse_args()

    module = Module()
    result = module.run(args.url, args.depth, args.timeout)
    print(json.dumps(result, ensure_ascii=False))

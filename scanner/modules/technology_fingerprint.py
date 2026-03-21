"""
Technology Fingerprinting — détecte les technologies utilisées par le site cible.
"""
import sys, os, argparse, time, json, re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.base_module import BaseModule

SIGNATURES = {
    # CMS
    "WordPress":  [r"wp-content/", r"wp-includes/", r"wp-login\.php", r"WordPress"],
    "Drupal":     [r"Drupal", r"/sites/default/files/", r"drupal\.js"],
    "Joomla":     [r"Joomla!", r"/components/com_", r"joomla"],
    "PrestaShop": [r"prestashop", r"/modules/", r"PrestaShop"],
    "Magento":    [r"Magento", r"mage/cookies", r"/skin/frontend/"],
    # Frameworks
    "Laravel":    [r"laravel_session", r"laravel", r"XSRF-TOKEN"],
    "Django":     [r"csrfmiddlewaretoken", r"Django", r"django"],
    "Rails":      [r"_rails_session", r"rails", r"X-Powered-By: Phusion Passenger"],
    "Symfony":    [r"symfony", r"sf_redirect", r"Symfony"],
    "Spring":     [r"JSESSIONID", r"spring", r"X-Application-Context"],
    # Serveurs
    "Apache":     [r"Apache/", r"Server: Apache"],
    "Nginx":      [r"nginx/", r"Server: nginx"],
    "IIS":        [r"Microsoft-IIS", r"X-Powered-By: ASP\.NET"],
    "Lighttpd":   [r"lighttpd/"],
    # Langages
    "PHP":        [r"X-Powered-By: PHP", r"\.php", r"PHPSESSID"],
    "Python":     [r"X-Powered-By: Python", r"Python/"],
    "Ruby":       [r"X-Powered-By: Phusion", r"_ruby_"],
    "ASP.NET":    [r"X-Powered-By: ASP\.NET", r"ASP\.NET", r"\.aspx"],
    # CDN / Analytics
    "Cloudflare": [r"cloudflare", r"CF-Ray", r"__cfduid"],
    "AWS":        [r"AmazonS3", r"X-Amz", r"amazonaws\.com"],
    "Google Analytics": [r"google-analytics\.com", r"ga\.js", r"gtag/js"],
    "jQuery":     [r"jquery", r"jQuery"],
    "React":      [r"react", r"__react", r"_reactRoot"],
    "Vue.js":     [r"vue\.js", r"__vue__", r"data-v-"],
    "Angular":    [r"ng-version", r"angular\.js", r"ng-app"],
}


class TechnologyFingerprint(BaseModule):

    def run(self, url: str, depth: str = "normal", timeout: int = 30) -> dict:
        start = time.time()
        module = "technology_fingerprint"
        try:
            import requests
            import warnings
            warnings.filterwarnings("ignore")

            base = url if url.startswith(("http://", "https://")) else f"http://{url}"
            session = requests.Session()
            session.headers["User-Agent"] = "VulnScan-Pro/1.0"
            session.verify = False

            try:
                r = session.get(base, timeout=10, allow_redirects=True)
            except Exception as e:
                return self.error(module, str(e), int((time.time() - start) * 1000))

            # Combine headers + body for analysis
            headers_str = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            cookies_str = "\n".join(f"{k}={v}" for k, v in r.cookies.items())
            body_sample = r.text[:50000]
            haystack = "\n".join([headers_str, cookies_str, body_sample])

            detected = []
            for tech, patterns in SIGNATURES.items():
                for pat in patterns:
                    if re.search(pat, haystack, re.IGNORECASE):
                        detected.append(tech)
                        break

            vulns = []
            if detected:
                vulns.append(self.vuln(
                    name=f"Technologies identifiées ({len(detected)})",
                    severity="LOW",
                    cvss_score=2.5,
                    endpoint=base,
                    description=(
                        f"Les technologies suivantes ont été détectées sur le site : {', '.join(detected)}. "
                        "Ces informations aident un attaquant à cibler des vulnérabilités connues "
                        "spécifiques à ces technologies."
                    ),
                    recommendation=(
                        "Masquez les en-têtes révélant les technologies (Server, X-Powered-By). "
                        "Gardez tous les composants à jour. "
                        "Utilisez un WAF pour masquer les signatures des frameworks."
                    ),
                ))

            duration = int((time.time() - start) * 1000)
            return self.result(module, vulns, duration)
        except Exception as e:
            duration = int((time.time() - start) * 1000)
            return self.error(module, str(e), duration)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url",     required=True)
    parser.add_argument("--depth",   default="normal")
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()
    print(json.dumps(TechnologyFingerprint().run(args.url, args.depth, args.timeout)))

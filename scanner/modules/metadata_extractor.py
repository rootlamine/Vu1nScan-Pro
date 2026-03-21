"""
Metadata Extractor — extrait les métadonnées des PDF et images trouvés sur le site.
"""
import sys, os, argparse, time, json, re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.base_module import BaseModule

OSINT_REFS = [
    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/",
    "https://www.sans.org/white-papers/33",
]

SENSITIVE_META_KEYS = [
    "author", "creator", "producer", "company", "manager",
    "last modified by", "template", "application",
]

FILE_EXTENSIONS = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"]
IMAGE_EXTENSIONS = [".jpg", ".jpeg", ".png", ".tiff", ".tif"]


class MetadataExtractor(BaseModule):

    def _crawl_links(self, base_url: str, session, extensions: list, limit: int = 10) -> list:
        """Trouve les liens vers des fichiers avec les extensions données."""
        from bs4 import BeautifulSoup
        from urllib.parse import urljoin, urlparse
        try:
            r = session.get(base_url, timeout=10, allow_redirects=True)
            soup = BeautifulSoup(r.text, "html.parser")
            found = []
            for tag in soup.find_all(["a", "link"], href=True):
                href = tag["href"]
                full_url = urljoin(base_url, href)
                if any(full_url.lower().endswith(ext) for ext in extensions):
                    found.append(full_url)
                    if len(found) >= limit:
                        break
            return found
        except Exception:
            return []

    def _extract_pdf_meta(self, content: bytes) -> dict:
        try:
            import io
            from pypdf import PdfReader
            reader = PdfReader(io.BytesIO(content))
            meta = reader.metadata or {}
            return {k.lstrip("/"): str(v) for k, v in meta.items()}
        except Exception:
            return {}

    def _extract_image_meta(self, content: bytes) -> dict:
        try:
            import io
            from PIL import Image
            from PIL.ExifTags import TAGS
            img = Image.open(io.BytesIO(content))
            exif = img._getexif() if hasattr(img, "_getexif") and img._getexif() else {}
            if not exif:
                return {}
            return {TAGS.get(k, str(k)): str(v)[:200] for k, v in exif.items()}
        except Exception:
            return {}

    def run(self, url: str, depth: str = "normal", timeout: int = 30) -> dict:
        start = time.time()
        module = "metadata_extractor"
        try:
            import requests
            import warnings
            warnings.filterwarnings("ignore")

            base = url if url.startswith(("http://", "https://")) else f"http://{url}"
            session = requests.Session()
            session.headers["User-Agent"] = "VulnScan-Pro/1.0"
            session.verify = False

            limit = 15 if depth == "deep" else 8 if depth == "normal" else 4

            pdf_links   = self._crawl_links(base, session, FILE_EXTENSIONS, limit)
            image_links = self._crawl_links(base, session, IMAGE_EXTENSIONS, limit // 2)

            vulns = []

            for file_url in pdf_links:
                try:
                    r = session.get(file_url, timeout=12, stream=True)
                    content = b"".join(list(r.iter_content(1024 * 512))[:1])  # max 512KB
                    meta = self._extract_pdf_meta(content)

                    sensitive = {k: v for k, v in meta.items()
                                 if any(s in k.lower() for s in SENSITIVE_META_KEYS)}

                    if sensitive or meta:
                        leaked = "; ".join(f"{k}={v}" for k, v in list(sensitive.items())[:5])
                        vulns.append(self.vuln(
                            name="Métadonnées sensibles dans document",
                            severity="MEDIUM",
                            cvss_score=4.5,
                            endpoint=file_url,
                            description=(
                                f"Le document exposé contient des métadonnées révélant des informations internes : "
                                f"{leaked or ', '.join(list(meta.keys())[:5])}. "
                                "Ces données peuvent révéler des noms d'employés, logiciels internes, chemins réseau."
                            ),
                            recommendation=(
                                "Nettoyez les métadonnées avant publication (File > Properties > Remove Personal Info). "
                                "Utilisez des outils comme ExifTool ou mat2 pour anonymiser les documents."
                            ),
                            references=OSINT_REFS,
                        ))
                except Exception:
                    pass

            for img_url in image_links:
                try:
                    r = session.get(img_url, timeout=10, stream=True)
                    content = b"".join(list(r.iter_content(1024 * 512))[:1])
                    exif = self._extract_image_meta(content)

                    gps_keys = [k for k in exif if "GPS" in str(k) or "gps" in str(k).lower()]
                    if gps_keys or "Make" in exif or "Model" in exif:
                        leaked = "; ".join(f"{k}={exif[k]}" for k in list(exif.keys())[:4])
                        vulns.append(self.vuln(
                            name="Données EXIF exposées dans image",
                            severity="MEDIUM" if gps_keys else "LOW",
                            cvss_score=4.5 if gps_keys else 3.1,
                            endpoint=img_url,
                            description=(
                                f"L'image contient des données EXIF : {leaked}. "
                                + ("Les coordonnées GPS révèlent la localisation physique." if gps_keys else "")
                            ),
                            recommendation=(
                                "Supprimez les métadonnées EXIF avant de publier des images. "
                                "Utilisez ImageMagick (mogrify -strip) ou PIL pour nettoyer les EXIF."
                            ),
                            references=OSINT_REFS,
                        ))
                except Exception:
                    pass

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
    print(json.dumps(MetadataExtractor().run(args.url, args.depth, args.timeout)))

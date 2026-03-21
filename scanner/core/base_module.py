"""
Classe de base pour tous les modules de scan VulnScan Pro.
Chaque module hérite de BaseModule et implémente la méthode run().
"""
import time
from abc import ABC, abstractmethod


class BaseModule(ABC):

    @abstractmethod
    def run(self, url: str, depth: str = "normal", timeout: int = 30) -> dict:
        pass

    def result(self, module_name: str, vulnerabilities: list, duration_ms: int) -> dict:
        return {
            "module":          module_name,
            "status":          "success",
            "duration_ms":     duration_ms,
            "error":           None,
            "vulnerabilities": vulnerabilities,
        }

    def error(self, module_name: str, message: str, duration_ms: int = 0) -> dict:
        return {
            "module":          module_name,
            "status":          "error",
            "duration_ms":     duration_ms,
            "error":           message,
            "vulnerabilities": [],
        }

    def vuln(self, name: str, severity: str, cvss_score: float,
             endpoint: str, description: str, recommendation: str,
             parameter: str = None, payload: str = None, cve_id: str = None) -> dict:
        return {
            "name":           name,
            "severity":       severity,
            "cvss_score":     cvss_score,
            "endpoint":       endpoint,
            "parameter":      parameter,
            "description":    description,
            "payload":        payload,
            "recommendation": recommendation,
            "cve_id":         cve_id,
        }

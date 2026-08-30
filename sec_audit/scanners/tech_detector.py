"""
Technology Stack and CMS Fingerprinting Engine
Detects web servers, backend frameworks, CMSs, and frontend libraries from HTTP responses.
"""

import re
import requests
from typing import List, Dict, Tuple, Any
from ..config import DEFAULT_TIMEOUT, DEFAULT_USER_AGENT


class TechDetector:
    """
    Fingerprints server technologies, CMSs, and frontend frameworks.
    """

    SIGNATURES = [
        # Web Servers
        {"name": "Nginx", "category": "Web Server", "header": ("Server", r"nginx(?:/([0-9\.]+))?")},
        {"name": "Apache HTTP Server", "category": "Web Server", "header": ("Server", r"Apache(?:/([0-9\.]+))?")},
        {"name": "Microsoft-IIS", "category": "Web Server", "header": ("Server", r"Microsoft-IIS(?:/([0-9\.]+))?")},
        {"name": "Caddy", "category": "Web Server", "header": ("Server", r"Caddy")},
        {"name": "Cloudflare", "category": "CDN / Reverse Proxy", "header": ("Server", r"cloudflare")},

        # Backend Frameworks
        {"name": "Laravel", "category": "Backend Framework (PHP)", "cookie": r"laravel_session|XSRF-TOKEN", "header": ("X-Powered-By", r"Laravel")},
        {"name": "Django", "category": "Backend Framework (Python)", "cookie": r"csrftoken|sessionid"},
        {"name": "Express.js", "category": "Backend Framework (Node.js)", "header": ("X-Powered-By", r"Express")},
        {"name": "ASP.NET", "category": "Backend Framework (.NET)", "header": ("X-Powered-By", r"ASP\.NET"), "cookie": r"ASP\.NET_SessionId"},
        {"name": "Ruby on Rails", "category": "Backend Framework (Ruby)", "header": ("X-Powered-By", r"Phusion Passenger"), "cookie": r"_session_id"},
        {"name": "Spring Boot", "category": "Backend Framework (Java)", "cookie": r"JSESSIONID"},

        # CMS
        {"name": "WordPress", "category": "Content Management System (CMS)", "html": r"wp-content|wp-includes|wp-json"},
        {"name": "Drupal", "category": "Content Management System (CMS)", "header": ("X-Generator", r"Drupal"), "html": r"Drupal\.settings"},
        {"name": "Joomla", "category": "Content Management System (CMS)", "header": ("X-Content-Encoded-By", r"Joomla")},

        # Frontend Frameworks
        {"name": "Next.js", "category": "Frontend Framework (React)", "html": r"__NEXT_DATA__|/_next/"},
        {"name": "Nuxt.js", "category": "Frontend Framework (Vue)", "html": r"__NUXT__|/_nuxt/"},
        {"name": "React", "category": "JavaScript Library", "html": r"data-reactroot|react-dom"},
        {"name": "Vue.js", "category": "JavaScript Framework", "html": r"data-v-[a-z0-9]+|vue\.runtime"},
        {"name": "Angular", "category": "JavaScript Framework", "html": r"ng-version|ng-app"},
        {"name": "Tailwind CSS", "category": "CSS Framework", "html": r"tailwind(?:css)?"},
        {"name": "Bootstrap", "category": "CSS Framework", "html": r"bootstrap(?:\.min)?\.(?:css|js)"},
        {"name": "Alpine.js", "category": "JavaScript Library", "html": r"x-data|alpine(?:\.min)?\.js"},
        {"name": "jQuery", "category": "JavaScript Library", "html": r"jquery(?:\.min)?\.js"},
    ]

    def __init__(self, target_url: str, timeout: int = DEFAULT_TIMEOUT):
        self.target_url = target_url
        self.timeout = timeout

    def detect(self) -> List[Dict[str, str]]:
        detected: List[Dict[str, str]] = []
        try:
            resp = requests.get(
                self.target_url,
                headers={"User-Agent": DEFAULT_USER_AGENT},
                timeout=self.timeout,
                verify=False,
            )
        except Exception:
            return detected

        headers = resp.headers
        cookies = " ".join([f"{c.name}={c.value}" for c in resp.cookies])
        body = resp.text[:100000]  # First 100KB is plenty for signatures

        seen_names = set()

        for sig in self.SIGNATURES:
            name = sig["name"]
            category = sig["category"]
            matched = False
            version = None

            # Check Header
            if "header" in sig:
                hdr_name, hdr_regex = sig["header"]
                val = headers.get(hdr_name, "")
                m = re.search(hdr_regex, val, re.IGNORECASE)
                if m:
                    matched = True
                    if m.groups() and m.group(1):
                        version = m.group(1)

            # Check Cookie
            if not matched and "cookie" in sig:
                if re.search(sig["cookie"], cookies, re.IGNORECASE):
                    matched = True

            # Check HTML body
            if not matched and "html" in sig:
                if re.search(sig["html"], body, re.IGNORECASE):
                    matched = True

            if matched and name not in seen_names:
                seen_names.add(name)
                detected.append({
                    "name": f"{name} {version}" if version else name,
                    "category": category,
                })

        return detected

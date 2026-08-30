"""
Auto-Fix Snippet Generator for Security Headers and Configurations
"""

from typing import Dict, Optional


class FixGenerator:
    """
    Generates ready-to-copy server and framework configuration snippets
    for remediating missing security headers and common findings.
    """

    @staticmethod
    def get_header_fix(header_name: str) -> Optional[Dict[str, str]]:
        header_map = {
            "Strict-Transport-Security": {
                "nginx": "add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' always;",
                "apache": "Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload'",
                "express": "app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));",
                "laravel": "// in app/Http/Middleware/SecurityHeaders.php\n$response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');",
                "django": "SECURE_HSTS_SECONDS = 31536000\nSECURE_HSTS_INCLUDE_SUBDOMAINS = True\nSECURE_HSTS_PRELOAD = True",
            },
            "Content-Security-Policy": {
                "nginx": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; object-src 'none'; frame-ancestors 'self'; base-uri 'self';\" always;",
                "apache": "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'self'; base-uri 'self';\"",
                "express": "app.use(helmet.contentSecurityPolicy({\n  directives: {\n    defaultSrc: [\"'self'\"],\n    scriptSrc: [\"'self'\"],\n    styleSrc: [\"'self'\", \"'unsafe-inline'\"],\n    objectSrc: [\"'none'\"],\n    frameAncestors: [\"'self'\"],\n    baseUri: [\"'self'\"]\n  }\n}));",
                "laravel": "$response->headers->set('Content-Security-Policy', \"default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'self';\");",
                "django": "# Install django-csp and add to settings.py:\nCSP_DEFAULT_SRC = (\"'self'\",)\nCSP_SCRIPT_SRC = (\"'self'\",)\nCSP_OBJECT_SRC = (\"'none'\",)\nCSP_FRAME_ANCESTORS = (\"'self'\",)",
            },
            "X-Content-Type-Options": {
                "nginx": "add_header X-Content-Type-Options 'nosniff' always;",
                "apache": "Header always set X-Content-Type-Options 'nosniff'",
                "express": "app.use(helmet.noSniff());",
                "laravel": "$response->headers->set('X-Content-Type-Options', 'nosniff');",
                "django": "SECURE_CONTENT_TYPE_NOSNIFF = True",
            },
            "X-Frame-Options": {
                "nginx": "add_header X-Frame-Options 'SAMEORIGIN' always;",
                "apache": "Header always set X-Frame-Options 'SAMEORIGIN'",
                "express": "app.use(helmet.frameguard({ action: 'sameorigin' }));",
                "laravel": "$response->headers->set('X-Frame-Options', 'SAMEORIGIN');",
                "django": "X_FRAME_OPTIONS = 'SAMEORIGIN'",
            },
            "Referrer-Policy": {
                "nginx": "add_header Referrer-Policy 'strict-origin-when-cross-origin' always;",
                "apache": "Header always set Referrer-Policy 'strict-origin-when-cross-origin'",
                "express": "app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));",
                "laravel": "$response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');",
                "django": "SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'",
            },
            "Permissions-Policy": {
                "nginx": "add_header Permissions-Policy 'camera=(), microphone=(), geolocation=()' always;",
                "apache": "Header always set Permissions-Policy 'camera=(), microphone=(), geolocation=()'",
                "express": "app.use((req, res, next) => {\n  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');\n  next();\n});",
                "laravel": "$response->headers->set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');",
                "django": "# In custom middleware:\nresponse['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'",
            },
        }

        return header_map.get(header_name)

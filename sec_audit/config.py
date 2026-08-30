"""
Configuration, Constants, and Advanced Rulesets for SecAudit 2.0
"""

DEFAULT_TIMEOUT = 10
DEFAULT_USER_AGENT = "SecAudit-Enterprise/2.0 (Defensive Security & Compliance Auditor)"

# Standard Security Headers
SECURITY_HEADERS_RULES = {
    "Strict-Transport-Security": {
        "title": "Missing Strict-Transport-Security (HSTS) Header",
        "severity": "HIGH",
        "cwe": "CWE-319",
        "cvss": 7.5,
        "description": "HTTP Strict Transport Security (HSTS) informs browsers that the site should only be accessed using HTTPS.",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to web server response headers.",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
    },
    "Content-Security-Policy": {
        "title": "Missing Content-Security-Policy (CSP) Header",
        "severity": "HIGH",
        "cwe": "CWE-1021",
        "cvss": 7.5,
        "description": "Content-Security-Policy helps prevent Cross-Site Scripting (XSS), clickjacking, and other code injection attacks.",
        "remediation": "Define a robust CSP header (e.g. Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'self';).",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
    },
    "X-Content-Type-Options": {
        "title": "Missing X-Content-Type-Options Header",
        "severity": "MEDIUM",
        "cwe": "CWE-693",
        "cvss": 5.3,
        "description": "The X-Content-Type-Options: nosniff header prevents MIME-sniffing away from the declared content-type.",
        "remediation": "Add 'X-Content-Type-Options: nosniff' header to all HTTP responses.",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
    },
    "X-Frame-Options": {
        "title": "Missing X-Frame-Options Header",
        "severity": "MEDIUM",
        "cwe": "CWE-1021",
        "cvss": 5.3,
        "description": "X-Frame-Options prevents clickjacking by restricting frame/iframe rendering.",
        "remediation": "Add 'X-Frame-Options: SAMEORIGIN' or 'X-Frame-Options: DENY' to your web server headers.",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
    },
    "Referrer-Policy": {
        "title": "Missing or Weak Referrer-Policy Header",
        "severity": "LOW",
        "cwe": "CWE-200",
        "cvss": 3.1,
        "description": "Referrer-Policy controls how much referrer information is leaked with outgoing requests.",
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer' to your headers.",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
    },
    "Permissions-Policy": {
        "title": "Missing Permissions-Policy Header",
        "severity": "LOW",
        "cwe": "CWE-693",
        "cvss": 3.1,
        "description": "Permissions-Policy allows declaring which browser features (camera, microphone, geolocation) are enabled.",
        "remediation": "Add 'Permissions-Policy: camera=(), microphone=(), geolocation=()' to restrict unused browser features.",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
    },
}

LEAKED_SERVER_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Runtime",
    "Via",
]

SENSITIVE_PATHS = [
    {"path": "/.env", "name": "Environment Variables File (.env)", "severity": "CRITICAL", "keywords": ["DB_PASSWORD", "SECRET_KEY", "API_KEY", "APP_ENV", "AWS_ACCESS_KEY", "APP_KEY"]},
    {"path": "/.env.backup", "name": "Environment Variables Backup", "severity": "CRITICAL", "keywords": ["DB_PASSWORD", "SECRET_KEY", "APP_KEY"]},
    {"path": "/.git/HEAD", "name": "Git Repository Metadata (.git/HEAD)", "severity": "CRITICAL", "keywords": ["ref: refs/"]},
    {"path": "/.git/config", "name": "Git Config File (.git/config)", "severity": "HIGH", "keywords": ["[core]", "repositoryformatversion"]},
    {"path": "/wp-config.php.bak", "name": "WordPress Config Backup", "severity": "CRITICAL", "keywords": ["DB_NAME", "DB_PASSWORD", "table_prefix"]},
    {"path": "/config.php.bak", "name": "PHP Configuration Backup", "severity": "HIGH", "keywords": ["<?php", "password", "db"]},
    {"path": "/phpinfo.php", "name": "Exposed PHPInfo Diagnostic Page", "severity": "MEDIUM", "keywords": ["PHP Version", "Configuration File (php.ini) Path"]},
    {"path": "/info.php", "name": "Exposed PHP Info Diagnostic Page", "severity": "MEDIUM", "keywords": ["PHP Version"]},
    {"path": "/storage/logs/laravel.log", "name": "Laravel Application Log", "severity": "HIGH", "keywords": ["[stacktrace]", "local.ERROR"]},
    {"path": "/app.log", "name": "Application Log File", "severity": "MEDIUM", "keywords": ["ERROR", "DEBUG", "TRACE"]},
    {"path": "/server-status", "name": "Apache Server Status Page", "severity": "LOW", "keywords": ["Apache Server Status for"]},
    {"path": "/docker-compose.yml", "name": "Exposed Docker Compose File", "severity": "HIGH", "keywords": ["services:", "version:"]},
    {"path": "/swagger.json", "name": "Exposed Swagger/OpenAPI Spec", "severity": "LOW", "keywords": ["\"swagger\":", "\"openapi\":"]},
    {"path": "/robots.txt", "name": "Robots.txt Inspection", "severity": "INFO", "keywords": ["Disallow:", "User-agent:"]},
]

SAST_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".env", ".json", 
    ".yaml", ".yml", ".ini", ".conf", ".sql", ".go", ".rb", ".java", 
    ".cs", ".rs", ".vue", ".svelte", ".html", ".sh"
}

IGNORE_DIRS = {
    "node_modules", ".git", ".idea", ".vscode", "venv", ".venv", 
    "env", "__pycache__", "dist", "build", "vendor", ".next", ".nuxt",
    "target", ".turbo"
}

# License classification for SCA
RESTRICTIVE_LICENSES = {
    "AGPL-3.0", "AGPL-1.0", "GPL-3.0", "GPL-2.0", "GPL-1.0", 
    "SSPL-1.0", "EUPL-1.2", "OSL-3.0", "CPAL-1.0"
}
PERMISSIVE_LICENSES = {
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unlicense", "CC0-1.0"
}

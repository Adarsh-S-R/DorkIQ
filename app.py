from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List, Optional
import re
import os
import uvicorn
try:
    import markdown  # type: ignore
except Exception:
    markdown = None

app = FastAPI(
    title="DorkIQ", 
    version="2.0.0",
    description="See the dorks before anyone else - Advanced vulnerability discovery platform using Google Dorks",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# === Models ===
class DorkRequest(BaseModel):
    domain: str
    industry: Optional[str] = None
    tld: Optional[str] = None
    include_subdomains: bool = False
    vulnerability_category: Optional[str] = None
    advanced_mode: bool = False

class Dork(BaseModel):
    category: str
    intent_category: str
    name: str
    dork: str
    owasp: str
    notes: str
    example_usage: str
    tags: Optional[List[str]] = []

# === Helpers ===
def normalize_domain(domain: str) -> str:
    domain = re.sub(r'^https?://', '', domain.lower())
    return domain.rstrip('/')

# === Advanced Dork Generator ===
def generate_dorks(domain: str, industry: Optional[str] = None, tld: Optional[str] = None,
                   include_subdomains: bool = False, vulnerability_category: Optional[str] = None,
                   advanced_mode: bool = False) -> List[Dork]:
    normalized_domain = normalize_domain(domain)
    site_prefix = f"site:{normalized_domain}"
    if include_subdomains:
        site_prefix = f"site:*.{normalized_domain}"

    dorks: List[Dork] = []

    # Comprehensive vulnerability database
    vulnerability_database = {
        "sql": [
            {"name": "SQL Injection - ID Parameter", "pattern": f"inurl:id= {site_prefix}", "owasp": "A1", "notes": "Search for ID parameters vulnerable to SQL injection", "tags": ["SQLi", "Parameter"]},
            {"name": "SQL Injection - User Parameter", "pattern": f"inurl:user= {site_prefix}", "owasp": "A1", "notes": "User parameters often vulnerable to SQL injection", "tags": ["SQLi", "User"]},
            {"name": "SQL Injection - Login Forms", "pattern": f"inurl:login {site_prefix} intext:password", "owasp": "A1", "notes": "Login forms with SQL injection vulnerabilities", "tags": ["SQLi", "Login"]},
            {"name": "SQL Injection - Search Forms", "pattern": f"inurl:search {site_prefix} intext:query", "owasp": "A1", "notes": "Search functionality vulnerable to SQL injection", "tags": ["SQLi", "Search"]},
            {"name": "SQL Injection - Product ID", "pattern": f"inurl:product_id= {site_prefix}", "owasp": "A1", "notes": "E-commerce product ID parameters", "tags": ["SQLi", "E-commerce"]},
            {"name": "SQL Injection - Category Parameter", "pattern": f"inurl:cat= {site_prefix}", "owasp": "A1", "notes": "Category parameters in content management systems", "tags": ["SQLi", "CMS"]},
            {"name": "SQL Injection - News ID", "pattern": f"inurl:news_id= {site_prefix}", "owasp": "A1", "notes": "News article ID parameters", "tags": ["SQLi", "News"]},
            {"name": "SQL Injection - Forum Posts", "pattern": f"inurl:post_id= {site_prefix}", "owasp": "A1", "notes": "Forum post ID parameters", "tags": ["SQLi", "Forum"]},
        ],
        "xss": [
            {"name": "XSS - Search Parameter", "pattern": f"inurl:search {site_prefix} intext:q=", "owasp": "A3", "notes": "Search parameters vulnerable to reflected XSS", "tags": ["XSS", "Reflected"]},
            {"name": "XSS - Error Messages", "pattern": f"inurl:error {site_prefix} intext:message", "owasp": "A3", "notes": "Error messages that may reflect user input", "tags": ["XSS", "Error"]},
            {"name": "XSS - Contact Forms", "pattern": f"inurl:contact {site_prefix} intext:form", "owasp": "A3", "notes": "Contact forms vulnerable to XSS", "tags": ["XSS", "Form"]},
            {"name": "XSS - Comment Systems", "pattern": f"inurl:comment {site_prefix}", "owasp": "A3", "notes": "Comment systems with stored XSS vulnerabilities", "tags": ["XSS", "Stored"]},
            {"name": "XSS - Profile Pages", "pattern": f"inurl:profile {site_prefix}", "owasp": "A3", "notes": "User profile pages with XSS vulnerabilities", "tags": ["XSS", "Profile"]},
            {"name": "XSS - Newsletter Signup", "pattern": f"inurl:newsletter {site_prefix}", "owasp": "A3", "notes": "Newsletter signup forms", "tags": ["XSS", "Newsletter"]},
        ],
        "lfi": [
            {"name": "LFI - Include Parameter", "pattern": f"inurl:include= {site_prefix}", "owasp": "A4", "notes": "Local file inclusion via include parameter", "tags": ["LFI", "Include"]},
            {"name": "LFI - Page Parameter", "pattern": f"inurl:page= {site_prefix}", "owasp": "A4", "notes": "Page parameter for local file inclusion", "tags": ["LFI", "Page"]},
            {"name": "LFI - File Parameter", "pattern": f"inurl:file= {site_prefix}", "owasp": "A4", "notes": "File parameter vulnerable to LFI", "tags": ["LFI", "File"]},
            {"name": "LFI - Path Parameter", "pattern": f"inurl:path= {site_prefix}", "owasp": "A4", "notes": "Path parameter for directory traversal", "tags": ["LFI", "Path"]},
            {"name": "LFI - Document Parameter", "pattern": f"inurl:doc= {site_prefix}", "owasp": "A4", "notes": "Document parameter for LFI attacks", "tags": ["LFI", "Document"]},
        ],
        "rfi": [
            {"name": "RFI - URL Parameter", "pattern": f"inurl:url= {site_prefix}", "owasp": "A4", "notes": "URL parameter for remote file inclusion", "tags": ["RFI", "URL"]},
            {"name": "RFI - Include Parameter", "pattern": f"inurl:include= {site_prefix} intext:http", "owasp": "A4", "notes": "Include parameter with HTTP URLs", "tags": ["RFI", "Include"]},
            {"name": "RFI - Page Parameter", "pattern": f"inurl:page= {site_prefix} intext:http", "owasp": "A4", "notes": "Page parameter with external URLs", "tags": ["RFI", "Page"]},
        ],
        "auth": [
            {"name": "Authentication Bypass - Admin", "pattern": f"inurl:admin {site_prefix} intext:login", "owasp": "A5", "notes": "Admin login pages with bypass vulnerabilities", "tags": ["Auth", "Admin"]},
            {"name": "Authentication Bypass - Login", "pattern": f"inurl:login {site_prefix} intext:password", "owasp": "A5", "notes": "Login forms with authentication bypass", "tags": ["Auth", "Login"]},
            {"name": "Authentication Bypass - Dashboard", "pattern": f"inurl:dashboard {site_prefix}", "owasp": "A5", "notes": "Dashboard access without proper authentication", "tags": ["Auth", "Dashboard"]},
            {"name": "Authentication Bypass - Panel", "pattern": f"inurl:panel {site_prefix}", "owasp": "A5", "notes": "Control panels with weak authentication", "tags": ["Auth", "Panel"]},
            {"name": "Authentication Bypass - CPanel", "pattern": f"inurl:cpanel {site_prefix}", "owasp": "A5", "notes": "cPanel access vulnerabilities", "tags": ["Auth", "cPanel"]},
        ],
        "admin": [
            {"name": "Admin Panel Discovery", "pattern": f"inurl:admin {site_prefix}", "owasp": "A5", "notes": "Discover admin panels and interfaces", "tags": ["Admin", "Discovery"]},
            {"name": "Admin Panel - WordPress", "pattern": f"inurl:wp-admin {site_prefix}", "owasp": "A5", "notes": "WordPress admin panel", "tags": ["Admin", "WordPress"]},
            {"name": "Admin Panel - Joomla", "pattern": f"inurl:administrator {site_prefix}", "owasp": "A5", "notes": "Joomla administrator panel", "tags": ["Admin", "Joomla"]},
            {"name": "Admin Panel - Drupal", "pattern": f"inurl:user/login {site_prefix}", "owasp": "A5", "notes": "Drupal admin login", "tags": ["Admin", "Drupal"]},
            {"name": "Admin Panel - phpMyAdmin", "pattern": f"inurl:phpmyadmin {site_prefix}", "owasp": "A5", "notes": "phpMyAdmin database administration", "tags": ["Admin", "Database"]},
        ],
        "config": [
            {"name": "Configuration Files - PHP", "pattern": f"{site_prefix} filetype:php inurl:config", "owasp": "A6", "notes": "PHP configuration files", "tags": ["Config", "PHP"]},
            {"name": "Configuration Files - INI", "pattern": f"{site_prefix} filetype:ini", "owasp": "A6", "notes": "INI configuration files", "tags": ["Config", "INI"]},
            {"name": "Configuration Files - XML", "pattern": f"{site_prefix} filetype:xml inurl:config", "owasp": "A6", "notes": "XML configuration files", "tags": ["Config", "XML"]},
            {"name": "Configuration Files - YAML", "pattern": f"{site_prefix} filetype:yml", "owasp": "A6", "notes": "YAML configuration files", "tags": ["Config", "YAML"]},
            {"name": "Configuration Files - JSON", "pattern": f"{site_prefix} filetype:json inurl:config", "owasp": "A6", "notes": "JSON configuration files", "tags": ["Config", "JSON"]},
            {"name": "Configuration Files - Database", "pattern": f"{site_prefix} inurl:database.php", "owasp": "A6", "notes": "Database configuration files", "tags": ["Config", "Database"]},
        ],
        "backup": [
            {"name": "Backup Files - BAK", "pattern": f"{site_prefix} filetype:bak", "owasp": "A6", "notes": "BAK backup files", "tags": ["Backup", "BAK"]},
            {"name": "Backup Files - OLD", "pattern": f"{site_prefix} filetype:old", "owasp": "A6", "notes": "OLD backup files", "tags": ["Backup", "OLD"]},
            {"name": "Backup Files - SQL", "pattern": f"{site_prefix} filetype:sql", "owasp": "A6", "notes": "SQL database backups", "tags": ["Backup", "SQL"]},
            {"name": "Backup Files - ZIP", "pattern": f"{site_prefix} filetype:zip intext:backup", "owasp": "A6", "notes": "ZIP backup archives", "tags": ["Backup", "ZIP"]},
            {"name": "Backup Files - TAR", "pattern": f"{site_prefix} filetype:tar", "owasp": "A6", "notes": "TAR backup archives", "tags": ["Backup", "TAR"]},
            {"name": "Backup Files - GZ", "pattern": f"{site_prefix} filetype:gz", "owasp": "A6", "notes": "GZ compressed backups", "tags": ["Backup", "GZ"]},
        ],
        "logs": [
            {"name": "Log Files - Access", "pattern": f"{site_prefix} filetype:log intext:access", "owasp": "A6", "notes": "Web server access logs", "tags": ["Logs", "Access"]},
            {"name": "Log Files - Error", "pattern": f"{site_prefix} filetype:log intext:error", "owasp": "A6", "notes": "Error log files", "tags": ["Logs", "Error"]},
            {"name": "Log Files - Apache", "pattern": f"{site_prefix} inurl:access.log", "owasp": "A6", "notes": "Apache access logs", "tags": ["Logs", "Apache"]},
            {"name": "Log Files - Nginx", "pattern": f"{site_prefix} inurl:nginx.log", "owasp": "A6", "notes": "Nginx log files", "tags": ["Logs", "Nginx"]},
            {"name": "Log Files - PHP", "pattern": f"{site_prefix} inurl:php_errors.log", "owasp": "A6", "notes": "PHP error logs", "tags": ["Logs", "PHP"]},
        ],
        "api": [
            {"name": "API Documentation - Swagger", "pattern": f"{site_prefix} inurl:swagger", "owasp": "A6", "notes": "Swagger API documentation", "tags": ["API", "Swagger"]},
            {"name": "API Documentation - OpenAPI", "pattern": f"{site_prefix} inurl:api-docs", "owasp": "A6", "notes": "OpenAPI documentation", "tags": ["API", "OpenAPI"]},
            {"name": "API Endpoints - REST", "pattern": f"{site_prefix} inurl:api/ intext:json", "owasp": "A6", "notes": "REST API endpoints", "tags": ["API", "REST"]},
            {"name": "API Endpoints - GraphQL", "pattern": f"{site_prefix} inurl:graphql", "owasp": "A6", "notes": "GraphQL endpoints", "tags": ["API", "GraphQL"]},
            {"name": "API Keys - Configuration", "pattern": f"{site_prefix} intext:api_key", "owasp": "A6", "notes": "Exposed API keys in configuration", "tags": ["API", "Keys"]},
        ],
        "ssrf": [
            {"name": "SSRF - URL Parameter", "pattern": f"inurl:url= {site_prefix} intext:http", "owasp": "A10", "notes": "URL parameters for SSRF attacks", "tags": ["SSRF", "URL"]},
            {"name": "SSRF - Proxy Parameter", "pattern": f"inurl:proxy= {site_prefix}", "owasp": "A10", "notes": "Proxy parameters for SSRF", "tags": ["SSRF", "Proxy"]},
            {"name": "SSRF - Callback Parameter", "pattern": f"inurl:callback= {site_prefix}", "owasp": "A10", "notes": "Callback parameters for SSRF", "tags": ["SSRF", "Callback"]},
            {"name": "SSRF - Redirect Parameter", "pattern": f"inurl:redirect= {site_prefix} intext:http", "owasp": "A10", "notes": "Redirect parameters for SSRF", "tags": ["SSRF", "Redirect"]},
        ],
        "redirect": [
            {"name": "Open Redirect - URL Parameter", "pattern": f"inurl:url= {site_prefix} intext:http", "owasp": "A10", "notes": "URL parameters for open redirects", "tags": ["Redirect", "URL"]},
            {"name": "Open Redirect - Return Parameter", "pattern": f"inurl:return= {site_prefix}", "owasp": "A10", "notes": "Return parameters for redirects", "tags": ["Redirect", "Return"]},
            {"name": "Open Redirect - Next Parameter", "pattern": f"inurl:next= {site_prefix}", "owasp": "A10", "notes": "Next parameters for redirects", "tags": ["Redirect", "Next"]},
            {"name": "Open Redirect - Redirect Parameter", "pattern": f"inurl:redirect= {site_prefix}", "owasp": "A10", "notes": "Redirect parameters", "tags": ["Redirect", "Redirect"]},
        ],
        "info": [
            {"name": "Information Disclosure - Directory Listing", "pattern": f"{site_prefix} intitle:\"index of\"", "owasp": "A6", "notes": "Directory listing vulnerabilities", "tags": ["Info", "Directory"]},
            {"name": "Information Disclosure - Error Messages", "pattern": f"inurl:error {site_prefix} intext:stack trace", "owasp": "A6", "notes": "Error messages revealing stack traces", "tags": ["Info", "Error"]},
            {"name": "Information Disclosure - Version Info", "pattern": f"{site_prefix} intext:\"powered by\"", "owasp": "A6", "notes": "Technology stack information", "tags": ["Info", "Version"]},
            {"name": "Information Disclosure - Email Addresses", "pattern": f"{site_prefix} intext:@", "owasp": "A6", "notes": "Email addresses in public pages", "tags": ["Info", "Email"]},
            {"name": "Information Disclosure - Phone Numbers", "pattern": f"{site_prefix} intext:\"phone\" OR intext:\"tel:\"", "owasp": "A6", "notes": "Phone numbers in public content", "tags": ["Info", "Phone"]},
        ],
        "sensitive_docs": [
            {"name": "Confidential - PDF docs", "pattern": f"{site_prefix} filetype:pdf (confidential OR internal OR proprietary)", "owasp": "A6", "notes": "Confidential PDFs exposed", "tags": ["Sensitive", "Docs", "PDF"]},
            {"name": "Confidential - Word docs", "pattern": f"{site_prefix} (filetype:doc OR filetype:docx) (confidential OR internal)", "owasp": "A6", "notes": "DOC/DOCX with sensitive marking", "tags": ["Sensitive", "Docs", "Word"]},
            {"name": "Confidential - Spreadsheets", "pattern": f"{site_prefix} (filetype:xls OR filetype:xlsx OR filetype:csv) (password OR credentials OR users)", "owasp": "A6", "notes": "Credentials in spreadsheets", "tags": ["Sensitive", "Spreadsheets"]},
            {"name": "Confidential - Presentations", "pattern": f"{site_prefix} (filetype:ppt OR filetype:pptx) (confidential OR roadmap OR internal)", "owasp": "A6", "notes": "Roadmaps/strategy slides", "tags": ["Sensitive", "Slides"]},
            {"name": "Confidential - Text dumps", "pattern": f"{site_prefix} (filetype:txt OR filetype:log) (confidential OR leak OR dump)", "owasp": "A6", "notes": "Text/log leaks", "tags": ["Sensitive", "Text"]},
        ],
        # Professional add-ons for bug hunters
        "secrets": [
            {"name": "Secrets - .env files", "pattern": f"{site_prefix} filetype:env \"AWS_SECRET\" OR \"SECRET_KEY\"", "owasp": "A2", "notes": "Environment files leaking secrets", "tags": ["Secrets", "Credentials"]},
            {"name": "Secrets - Keys in files", "pattern": f"{site_prefix} (\"PRIVATE KEY\" OR \"BEGIN RSA\")", "owasp": "A2", "notes": "Private keys exposed in code or files", "tags": ["Secrets", "Keys"]},
            {"name": "Secrets - npm/yarn auth", "pattern": f"{site_prefix} (filename:.npmrc OR filename:.yarnrc) authToken", "owasp": "A2", "notes": "Registry tokens in config", "tags": ["Secrets", "Tokens"]},
            {"name": "Secrets - GitHub tokens", "pattern": f"site:github.com {normalized_domain} (token OR api_key OR password)", "owasp": "A2", "notes": "Tokens inside public repos mentioning target", "tags": ["Secrets", "GitHub"]},
        ],
        "cloud": [
            {"name": "AWS S3 Buckets", "pattern": f"site:s3.amazonaws.com {normalized_domain}", "owasp": "A6", "notes": "S3 buckets referencing target", "tags": ["Cloud", "AWS", "S3"]},
            {"name": "GCP Storage Buckets", "pattern": f"site:storage.googleapis.com {normalized_domain}", "owasp": "A6", "notes": "GCS buckets", "tags": ["Cloud", "GCP"]},
            {"name": "Azure Blobs", "pattern": f"site:blob.core.windows.net {normalized_domain}", "owasp": "A6", "notes": "Azure blob containers", "tags": ["Cloud", "Azure"]},
            {"name": "Exposed Cloud Credentials", "pattern": f"{site_prefix} (\"AWS_ACCESS_KEY_ID\" OR \"GOOGLE_APPLICATION_CREDENTIALS\")", "owasp": "A2", "notes": "Cloud keys/creds exposed", "tags": ["Cloud", "Secrets"]},
        ],
        "git": [
            {"name": "Exposed .git directory", "pattern": f"{site_prefix} inurl:.git/", "owasp": "A6", "notes": "Public .git folder leakage", "tags": ["Git", "Repo"]},
            {"name": "Exposed SVN/HG", "pattern": f"{site_prefix} (inurl:.svn/ OR inurl:.hg/)", "owasp": "A6", "notes": "Other VCS directories", "tags": ["VCS"]},
            {"name": "Public Gists mentioning target", "pattern": f"site:gist.github.com {normalized_domain}", "owasp": "A6", "notes": "Mentions in public gists", "tags": ["GitHub", "OSINT"]},
        ],
        "directories": [
            {"name": "Sensitive directories", "pattern": f"{site_prefix} inurl:(backup|private|tmp|old|conf|upload|uploads)", "owasp": "A6", "notes": "Common sensitive directories", "tags": ["Dirs"]},
            {"name": "Admin endpoints", "pattern": f"{site_prefix} inurl:(admin|manage|panel|dashboard)", "owasp": "A5", "notes": "Administrative areas", "tags": ["Admin", "Dirs"]},
        ],
        "headers": [
            {"name": "Security Headers Docs", "pattern": f"{site_prefix} intext:\"Content-Security-Policy\"", "owasp": "A6", "notes": "Pages referencing CSP", "tags": ["Headers", "CSP"]},
            {"name": "CORS docs/configs", "pattern": f"{site_prefix} intext:\"Access-Control-Allow-Origin\"", "owasp": "A6", "notes": "CORS configuration references", "tags": ["Headers", "CORS"]},
        ],
    }

    # If specific vulnerability category is requested
    if vulnerability_category and vulnerability_category != "all":
        if vulnerability_category in vulnerability_database:
            for dork_data in vulnerability_database[vulnerability_category]:
                dorks.append(Dork(
                    category="Critical" if vulnerability_category in ["sql", "lfi", "rfi"] else "High",
                    name=dork_data["name"],
                    dork=dork_data["pattern"],
                    owasp=dork_data["owasp"],
                    notes=dork_data["notes"],
                    example_usage=dork_data["pattern"],
                    tags=dork_data.get("tags", [])
                ))
    else:
        # Generate all categories
        for category, dork_list in vulnerability_database.items():
            for dork_data in dork_list:
                severity = "Critical" if category in ["sql", "lfi", "rfi"] else "High" if category in ["xss", "auth", "admin"] else "Medium" if category in ["config", "backup", "logs", "api"] else "Low"
                # Map to intent categories
                intent_mapping = {
                    "sql": "Vulnerable Technologies", "xss": "Vulnerable Technologies", "lfi": "Vulnerable Technologies",
                    "rfi": "Vulnerable Technologies", "auth": "Admin Panels & Dashboards", "admin": "Admin Panels & Dashboards",
                    "config": "Sensitive Files & Configs", "backup": "Backup & Old Versions", "logs": "Sensitive Files & Configs",
                    "api": "Vulnerable Technologies", "info": "Information Disclosure", "sensitive_docs": "Sensitive Files & Configs",
                    "secrets": "Credentials & Keys", "cloud": "Exposed Cameras / IoT", "git": "Code Repositories / Source",
                    "directories": "Directories & Indexing", "headers": "Information Disclosure"
                }
                intent_category = intent_mapping.get(category, "Misc Exploitable Data")
                dorks.append(Dork(
                    category=severity,
                    intent_category=intent_category,
                    name=dork_data["name"],
                    dork=dork_data["pattern"],
                    owasp=dork_data["owasp"],
                    notes=dork_data["notes"],
                    example_usage=dork_data["pattern"],
                    tags=dork_data.get("tags", [])
                ))

    # Add advanced mode dorks if enabled
    if advanced_mode:
        advanced_dorks = [
            {"name": "Advanced - Sensitive Directories", "pattern": f"site:{normalized_domain} (inurl:private OR inurl:secret)", "owasp": "A6", "notes": "Sensitive directory names", "tags": ["Advanced", "Directories"]},
            {"name": "Advanced - Development Files", "pattern": f"site:{normalized_domain} (filetype:dev OR filetype:test)", "owasp": "A6", "notes": "Development and test files", "tags": ["Advanced", "Dev"]},
            {"name": "Advanced - Temporary Files", "pattern": f"site:{normalized_domain} (filetype:tmp OR filetype:temp)", "owasp": "A6", "notes": "Temporary files", "tags": ["Advanced", "Temp"]},
            {"name": "Advanced - Cache Files", "pattern": f"site:{normalized_domain} filetype:cache", "owasp": "A6", "notes": "Cache files", "tags": ["Advanced", "Cache"]},
            {"name": "Advanced - Credentials in history", "pattern": f"site:{normalized_domain} (password OR secret OR token) (filetype:txt OR filetype:log)", "owasp": "A2", "notes": "Plaintext creds in text/logs", "tags": ["Advanced", "Secrets"]},
            {"name": "Advanced - Source archives", "pattern": f"site:{normalized_domain} (filetype:zip OR filetype:rar OR filetype:7z) (src OR source)", "owasp": "A6", "notes": "Source archives exposed", "tags": ["Advanced", "Archives"]},
            {"name": "Advanced - Jenkins/CI panels", "pattern": f"site:{normalized_domain} (intitle:Jenkins OR inurl:jenkins)", "owasp": "A5", "notes": "CI/CD admin consoles", "tags": ["Advanced", "CI"]},
            # New advanced dorks - fixed and expanded
            {"name": "PHP Extension w/ Parameters", "pattern": f"site:{normalized_domain} filetype:php inurl:?", "owasp": "A6", "notes": "PHP files with query parameters", "tags": ["Advanced", "PHP", "Parameters"]},
            {"name": "API Endpoints", "pattern": f"site:{normalized_domain} (inurl:api OR inurl:/rest OR inurl:/v1 OR inurl:/v2 OR inurl:/v3)", "owasp": "A6", "notes": "API endpoints and REST services", "tags": ["Advanced", "API", "REST"]},
            {"name": "Juicy Extensions", "pattern": f"site:{normalized_domain} (filetype:log OR filetype:txt OR filetype:conf OR filetype:cnf OR filetype:ini OR filetype:env OR filetype:sh OR filetype:bak OR filetype:backup OR filetype:swp OR filetype:old OR filetype:git OR filetype:svn OR filetype:htpasswd OR filetype:htaccess OR filetype:json)", "owasp": "A6", "notes": "Sensitive file extensions", "tags": ["Advanced", "Extensions", "Sensitive"]},
            {"name": "High Risk Directories - Conf", "pattern": f"site:{normalized_domain} inurl:conf", "owasp": "A6", "notes": "Configuration directories", "tags": ["Advanced", "Directories", "High-Risk"]},
            {"name": "High Risk Directories - Env", "pattern": f"site:{normalized_domain} inurl:env", "owasp": "A6", "notes": "Environment directories", "tags": ["Advanced", "Directories", "High-Risk"]},
            {"name": "High Risk Directories - CGI", "pattern": f"site:{normalized_domain} inurl:cgi", "owasp": "A6", "notes": "CGI directories", "tags": ["Advanced", "Directories", "High-Risk"]},
            {"name": "High Risk Directories - Bin", "pattern": f"site:{normalized_domain} inurl:bin", "owasp": "A6", "notes": "Binary directories", "tags": ["Advanced", "Directories", "High-Risk"]},
            {"name": "High Risk Directories - Etc", "pattern": f"site:{normalized_domain} inurl:etc", "owasp": "A6", "notes": "System directories", "tags": ["Advanced", "Directories", "High-Risk"]},
            {"name": "High Risk Directories - Root", "pattern": f"site:{normalized_domain} inurl:root", "owasp": "A6", "notes": "Root directories", "tags": ["Advanced", "Directories", "High-Risk"]},
            {"name": "High Risk Directories - SQL", "pattern": f"site:{normalized_domain} inurl:sql", "owasp": "A6", "notes": "SQL directories", "tags": ["Advanced", "Directories", "High-Risk"]},
            {"name": "High Risk Directories - Backup", "pattern": f"site:{normalized_domain} inurl:backup", "owasp": "A6", "notes": "Backup directories", "tags": ["Advanced", "Directories", "High-Risk"]},
            {"name": "High Risk Directories - Admin", "pattern": f"site:{normalized_domain} inurl:admin", "owasp": "A6", "notes": "Admin directories", "tags": ["Advanced", "Directories", "High-Risk"]},
            {"name": "High Risk Directories - PHP", "pattern": f"site:{normalized_domain} inurl:php", "owasp": "A6", "notes": "PHP directories", "tags": ["Advanced", "Directories", "High-Risk"]},
            {"name": "Server Errors", "pattern": f"site:{normalized_domain} (inurl:\"error\" OR intitle:\"exception\" OR intitle:\"failure\" OR intitle:\"server at\" OR inurl:exception OR \"database error\" OR \"SQL syntax\" OR \"undefined index\" OR \"unhandled exception\" OR \"stack trace\")", "owasp": "A6", "notes": "Server error pages and messages", "tags": ["Advanced", "Errors", "Debug"]},
            {"name": "XSS Prone Parameters", "pattern": f"site:{normalized_domain} (inurl:q= OR inurl:s= OR inurl:search= OR inurl:query= OR inurl:keyword= OR inurl:lang=)", "owasp": "A3", "notes": "Parameters prone to XSS attacks", "tags": ["Advanced", "XSS", "Parameters"]},
            {"name": "Open Redirect Prone Parameters", "pattern": f"site:{normalized_domain} (inurl:url= OR inurl:return= OR inurl:next= OR inurl:redirect= OR inurl:redir= OR inurl:ret= OR inurl:r2= OR inurl:page=) inurl:http", "owasp": "A10", "notes": "Parameters prone to open redirects", "tags": ["Advanced", "Redirect", "Parameters"]},
            {"name": "SQLi Prone Parameters", "pattern": f"site:{normalized_domain} (inurl:id= OR inurl:pid= OR inurl:category= OR inurl:cat= OR inurl:action= OR inurl:sid= OR inurl:dir=)", "owasp": "A1", "notes": "Parameters prone to SQL injection", "tags": ["Advanced", "SQLi", "Parameters"]},
            {"name": "SSRF Prone Parameters", "pattern": f"site:{normalized_domain} (inurl:http OR inurl:url= OR inurl:path= OR inurl:dest= OR inurl:html= OR inurl:data= OR inurl:domain= OR inurl:page=)", "owasp": "A10", "notes": "Parameters prone to SSRF attacks", "tags": ["Advanced", "SSRF", "Parameters"]},
            {"name": "LFI Prone Parameters", "pattern": f"site:{normalized_domain} (inurl:include OR inurl:dir OR inurl:detail= OR inurl:file= OR inurl:folder= OR inurl:inc= OR inurl:locate= OR inurl:doc= OR inurl:conf=)", "owasp": "A4", "notes": "Parameters prone to LFI attacks", "tags": ["Advanced", "LFI", "Parameters"]},
            {"name": "RCE Prone Parameters", "pattern": f"site:{normalized_domain} (inurl:cmd OR inurl:exec= OR inurl:query= OR inurl:code= OR inurl:do= OR inurl:run= OR inurl:read= OR inurl:ping=)", "owasp": "A9", "notes": "Parameters prone to RCE attacks", "tags": ["Advanced", "RCE", "Parameters"]},
            {"name": "File Upload Endpoints", "pattern": f"site:{normalized_domain} (intext:\"choose file\" OR intext:\"select file\" OR intext:\"upload PDF\")", "owasp": "A4", "notes": "File upload functionality", "tags": ["Advanced", "Upload", "Files"]},
            {"name": "API Docs", "pattern": f"site:{normalized_domain} (inurl:apidocs OR inurl:api-docs OR inurl:swagger OR inurl:api-explorer OR inurl:redoc OR inurl:openapi OR intitle:\"Swagger UI\")", "owasp": "A6", "notes": "API documentation endpoints", "tags": ["Advanced", "API", "Docs"]},
            {"name": "Login Pages", "pattern": f"site:{normalized_domain} (inurl:login OR inurl:signin OR intitle:login OR intitle:signin OR inurl:secure)", "owasp": "A5", "notes": "Authentication pages", "tags": ["Advanced", "Login", "Auth"]},
            {"name": "Test Environments", "pattern": f"site:{normalized_domain} (inurl:test OR inurl:env OR inurl:dev OR inurl:staging OR inurl:sandbox OR inurl:debug OR inurl:temp OR inurl:internal OR inurl:demo)", "owasp": "A6", "notes": "Development and test environments", "tags": ["Advanced", "Test", "Dev"]},
            {"name": "Sensitive Documents", "pattern": f"site:{normalized_domain} (filetype:txt OR filetype:pdf OR filetype:xml OR filetype:xls OR filetype:xlsx OR filetype:ppt OR filetype:pptx OR filetype:doc OR filetype:docx) (intext:\"confidential\" OR intext:\"Not for Public Release\" OR intext:\"internal use only\" OR intext:\"do not distribute\")", "owasp": "A6", "notes": "Sensitive documents exposed", "tags": ["Advanced", "Documents", "Sensitive"]},
            {"name": "Sensitive Parameters", "pattern": f"site:{normalized_domain} (inurl:email= OR inurl:phone= OR inurl:name= OR inurl:user=)", "owasp": "A6", "notes": "Parameters containing sensitive data", "tags": ["Advanced", "Parameters", "PII"]},
            {"name": "Adobe Experience Manager (AEM)", "pattern": f"site:{normalized_domain} (inurl:/content/usergenerated OR inurl:/content/dam OR inurl:/jcr:content OR inurl:/libs/granite OR inurl:/etc/clientlibs OR inurl:/content/geometrixx OR inurl:/bin/wcm OR inurl:crx/de)", "owasp": "A6", "notes": "AEM-specific paths and endpoints", "tags": ["Advanced", "AEM", "CMS"]},
            {"name": "Disclosed XSS and Open Redirects", "pattern": f"site:openbugbounty.org inurl:reports intext:\"{normalized_domain}\"", "owasp": "A6", "notes": "Public bug bounty disclosures", "tags": ["Advanced", "OSINT", "Bounty"]},
            {"name": "Google Groups", "pattern": f"site:groups.google.com \"{normalized_domain}\"", "owasp": "A6", "notes": "Mentions in Google Groups", "tags": ["Advanced", "OSINT", "Groups"]},
            {"name": "Code Leaks - Pastebin", "pattern": f"site:pastebin.com \"{normalized_domain}\"", "owasp": "A6", "notes": "Code leaks on Pastebin", "tags": ["Advanced", "OSINT", "Leaks"]},
            {"name": "Code Leaks - JSFiddle", "pattern": f"site:jsfiddle.net \"{normalized_domain}\"", "owasp": "A6", "notes": "Code leaks on JSFiddle", "tags": ["Advanced", "OSINT", "Leaks"]},
            {"name": "Code Leaks - CodeBeautify", "pattern": f"site:codebeautify.org \"{normalized_domain}\"", "owasp": "A6", "notes": "Code leaks on CodeBeautify", "tags": ["Advanced", "OSINT", "Leaks"]},
            {"name": "Code Leaks - CodePen", "pattern": f"site:codepen.io \"{normalized_domain}\"", "owasp": "A6", "notes": "Code leaks on CodePen", "tags": ["Advanced", "OSINT", "Leaks"]},
            {"name": "Cloud Storage - AWS S3", "pattern": f"site:s3.amazonaws.com \"{normalized_domain}\"", "owasp": "A6", "notes": "AWS S3 buckets", "tags": ["Advanced", "Cloud", "AWS"]},
            {"name": "Cloud Storage - Azure Blob", "pattern": f"site:blob.core.windows.net \"{normalized_domain}\"", "owasp": "A6", "notes": "Azure blob storage", "tags": ["Advanced", "Cloud", "Azure"]},
            {"name": "Cloud Storage - Google APIs", "pattern": f"site:googleapis.com \"{normalized_domain}\"", "owasp": "A6", "notes": "Google Cloud storage", "tags": ["Advanced", "Cloud", "GCP"]},
            {"name": "Cloud Storage - Google Drive", "pattern": f"site:drive.google.com \"{normalized_domain}\"", "owasp": "A6", "notes": "Google Drive shares", "tags": ["Advanced", "Cloud", "Drive"]},
            {"name": "Cloud Storage - Azure DevOps", "pattern": f"site:dev.azure.com \"{normalized_domain}\"", "owasp": "A6", "notes": "Azure DevOps repositories", "tags": ["Advanced", "Cloud", "Azure"]},
            {"name": "Cloud Storage - OneDrive", "pattern": f"site:onedrive.live.com \"{normalized_domain}\"", "owasp": "A6", "notes": "Microsoft OneDrive shares", "tags": ["Advanced", "Cloud", "Microsoft"]},
            {"name": "Cloud Storage - DigitalOcean", "pattern": f"site:digitaloceanspaces.com \"{normalized_domain}\"", "owasp": "A6", "notes": "DigitalOcean Spaces", "tags": ["Advanced", "Cloud", "DigitalOcean"]},
            {"name": "Cloud Storage - SharePoint", "pattern": f"site:sharepoint.com \"{normalized_domain}\"", "owasp": "A6", "notes": "SharePoint sites", "tags": ["Advanced", "Cloud", "Microsoft"]},
            {"name": "Cloud Storage - AWS S3 External", "pattern": f"site:s3-external-1.amazonaws.com \"{normalized_domain}\"", "owasp": "A6", "notes": "External AWS S3 buckets", "tags": ["Advanced", "Cloud", "AWS"]},
            {"name": "Cloud Storage - AWS S3 Dualstack", "pattern": f"site:s3.dualstack.us-east-1.amazonaws.com \"{normalized_domain}\"", "owasp": "A6", "notes": "Dualstack AWS S3 buckets", "tags": ["Advanced", "Cloud", "AWS"]},
            {"name": "Cloud Storage - Dropbox", "pattern": f"site:dropbox.com/s \"{normalized_domain}\"", "owasp": "A6", "notes": "Dropbox shared links", "tags": ["Advanced", "Cloud", "Dropbox"]},
            {"name": "Cloud Storage - Google Docs", "pattern": f"site:docs.google.com inurl:\"/d/\" \"{normalized_domain}\"", "owasp": "A6", "notes": "Google Docs shared documents", "tags": ["Advanced", "Cloud", "Docs"]},
            # Additional high-value dorks
            {"name": "phpinfo() Pages", "pattern": f"site:{normalized_domain} intitle:\"phpinfo()\"", "owasp": "A6", "notes": "phpinfo pages revealing server config", "tags": ["Advanced", "PHP", "Config"]},
            {"name": "WP Config Backups", "pattern": f"site:{normalized_domain} (\"wp-config.php~\" OR \"wp-config.php.bak\" OR \"wp-config.php.save\")", "owasp": "A6", "notes": "WP config backups or variants", "tags": ["Advanced", "WordPress", "Config"]},
            {"name": ".env.sample Files", "pattern": f"site:{normalized_domain} filetype:env intext:\"APP_KEY=\" OR intext:\"DB_PASSWORD\"", "owasp": "A2", "notes": "Environment sample files with secrets", "tags": ["Advanced", "Secrets", "Env"]},
            {"name": "Robots.txt Discovery", "pattern": f"site:{normalized_domain} inurl:robots.txt", "owasp": "A6", "notes": "Robots.txt files for path enumeration", "tags": ["Advanced", "Discovery", "SEO"]},
            {"name": "Sitemap.xml Discovery", "pattern": f"site:{normalized_domain} inurl:sitemap.xml", "owasp": "A6", "notes": "Sitemap files for path enumeration", "tags": ["Advanced", "Discovery", "SEO"]},
            {"name": "WP Content Uploads", "pattern": f"site:{normalized_domain} inurl:wp-content/uploads (filetype:zip OR filetype:sql)", "owasp": "A6", "notes": "WordPress uploads with backups", "tags": ["Advanced", "WordPress", "Uploads"]},
            {"name": "WP Login Pages", "pattern": f"site:{normalized_domain} inurl:wp-login.php", "owasp": "A5", "notes": "WordPress login pages", "tags": ["Advanced", "WordPress", "Login"]},
            {"name": "WP XMLRPC", "pattern": f"site:{normalized_domain} inurl:xmlrpc.php", "owasp": "A6", "notes": "WordPress XML-RPC endpoint", "tags": ["Advanced", "WordPress", "API"]},
            {"name": "Git Artifacts", "pattern": f"site:{normalized_domain} (inurl:.git/ OR inurl:.git/config OR \".git/index\")", "owasp": "A6", "notes": "Exposed Git repositories", "tags": ["Advanced", "Git", "Repo"]},
            {"name": "Composer Lock Files", "pattern": f"site:{normalized_domain} filetype:lock composer.lock \"packages\"", "owasp": "A6", "notes": "Composer dependency files", "tags": ["Advanced", "PHP", "Dependencies"]},
            {"name": "Package.json Files", "pattern": f"site:{normalized_domain} filetype:json \"private_key\" OR \"api_key\"", "owasp": "A2", "notes": "NPM package files with secrets", "tags": ["Advanced", "NodeJS", "Secrets"]},
            {"name": "Requirements.txt Files", "pattern": f"site:{normalized_domain} filetype:txt requirements.txt", "owasp": "A6", "notes": "Python requirements files", "tags": ["Advanced", "Python", "Dependencies"]},
            {"name": "phpMyAdmin Panels", "pattern": f"site:{normalized_domain} (intitle:\"phpMyAdmin\" OR inurl:phpmyadmin)", "owasp": "A5", "notes": "phpMyAdmin database consoles", "tags": ["Advanced", "Database", "Admin"]},
            {"name": "Elasticsearch Instances", "pattern": f"site:{normalized_domain} (inurl:9200/_search OR inurl:/elasticsearch)", "owasp": "A6", "notes": "Elasticsearch endpoints", "tags": ["Advanced", "Database", "Search"]},
            {"name": "Kibana Dashboards", "pattern": f"site:{normalized_domain} intitle:\"Kibana\"", "owasp": "A6", "notes": "Kibana visualization dashboards", "tags": ["Advanced", "Monitoring", "Kibana"]},
            {"name": "Grafana Dashboards", "pattern": f"site:{normalized_domain} intitle:\"Grafana\"", "owasp": "A6", "notes": "Grafana monitoring dashboards", "tags": ["Advanced", "Monitoring", "Grafana"]},
            {"name": "Docker Compose Files", "pattern": f"site:{normalized_domain} (inurl:docker-compose.yml OR filetype:yaml \"image:\")", "owasp": "A6", "notes": "Docker configuration files", "tags": ["Advanced", "Docker", "Config"]},
            {"name": "Kubernetes Dashboards", "pattern": f"site:{normalized_domain} inurl:\"kubernetes-dashboard\" OR inurl:\"/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard\"", "owasp": "A5", "notes": "Kubernetes admin consoles", "tags": ["Advanced", "Kubernetes", "Admin"]},
            {"name": "AWS S3 Bucket References", "pattern": f"site:{normalized_domain} intext:\"s3.amazonaws.com\"", "owasp": "A6", "notes": "References to S3 buckets in code", "tags": ["Advanced", "AWS", "S3"]},
            {"name": "PHP Backup Files", "pattern": f"site:{normalized_domain} filetype:php (\"wp-config.php~\" OR \"config.php~\" OR \"config.php.bak\")", "owasp": "A6", "notes": "PHP configuration backups", "tags": ["Advanced", "PHP", "Backup"]},
            {"name": "YAML Config Secrets", "pattern": f"site:{normalized_domain} filetype:yaml (\"password:\" OR \"secret:\" OR \"key:\")", "owasp": "A2", "notes": "YAML configs with secrets", "tags": ["Advanced", "Config", "Secrets"]},
            {"name": "Email Lists", "pattern": f"site:{normalized_domain} filetype:xls OR filetype:csv \"email\"", "owasp": "A6", "notes": "Exposed email lists in spreadsheets", "tags": ["Advanced", "PII", "Email"]},
            {"name": "OIDC Metadata", "pattern": f"site:{normalized_domain} inurl:\"/.well-known/openid-configuration\"", "owasp": "A6", "notes": "OpenID Connect configuration", "tags": ["Advanced", "OAuth", "SSO"]},
            {"name": "Index of Backups", "pattern": f"site:{normalized_domain} intitle:\"index of\" \"backup\"", "owasp": "A6", "notes": "Directory listings with backups", "tags": ["Advanced", "Directory", "Backup"]},
            {"name": "PHPUnit Debug", "pattern": f"site:{normalized_domain} inurl:phpunit", "owasp": "A6", "notes": "PHPUnit testing framework exposed", "tags": ["Advanced", "PHP", "Testing"]},
            {"name": "GitLab CI", "pattern": f"site:{normalized_domain} (inurl:gitlab-runner OR inurl:/ci/ OR \"gitlab-ci.yml\")", "owasp": "A6", "notes": "GitLab CI/CD configurations", "tags": ["Advanced", "GitLab", "CI"]},
            {"name": "CircleCI Configs", "pattern": f"site:{normalized_domain} (intitle:\"CircleCI\" OR \"bitbucket-pipelines.yml\")", "owasp": "A6", "notes": "CircleCI and Bitbucket pipelines", "tags": ["Advanced", "CI", "Bitbucket"]},
            {"name": "GitHub Secrets", "pattern": f"site:github.com \"{normalized_domain}\" (\"token\" OR \"api_key\" OR \"password\" OR \"SECRET_KEY\" OR \"AWS_ACCESS_KEY_ID\")", "owasp": "A2", "notes": "Secrets in public GitHub repos mentioning target", "tags": ["Advanced", "GitHub", "OSINT"]},
        ]
        
        for dork_data in advanced_dorks:
            # Map advanced dorks to intent categories
            advanced_intent_mapping = {
                "phpinfo": "Information Disclosure", "wp-config": "Sensitive Files & Configs", ".env": "Credentials & Keys",
                "robots.txt": "Directories & Indexing", "sitemap.xml": "Directories & Indexing", "wp-content": "Backup & Old Versions",
                "wp-login": "Login Pages / Panels", "xmlrpc": "Vulnerable Technologies", ".git": "Code Repositories / Source",
                "composer.lock": "Sensitive Files & Configs", "package.json": "Sensitive Files & Configs", "requirements.txt": "Sensitive Files & Configs",
                "phpmyadmin": "Admin Panels & Dashboards", "elasticsearch": "Database Dumps", "kibana": "Admin Panels & Dashboards",
                "grafana": "Admin Panels & Dashboards", "docker-compose": "Vulnerable Technologies", "kubernetes": "Vulnerable Technologies",
                "s3.amazonaws.com": "Cloud Storage", "openbugbounty": "Information Disclosure", "groups.google.com": "Information Disclosure",
                "pastebin": "Code Repositories / Source", "jsfiddle": "Code Repositories / Source", "codebeautify": "Code Repositories / Source",
                "codepen": "Code Repositories / Source", "s3.amazonaws.com": "Cloud Storage", "blob.core.windows.net": "Cloud Storage",
                "googleapis.com": "Cloud Storage", "drive.google.com": "Cloud Storage", "dev.azure.com": "Cloud Storage",
                "onedrive.live.com": "Cloud Storage", "digitaloceanspaces.com": "Cloud Storage", "sharepoint.com": "Cloud Storage",
                "s3-external-1.amazonaws.com": "Cloud Storage", "s3.dualstack.us-east-1.amazonaws.com": "Cloud Storage",
                "dropbox.com": "Cloud Storage", "docs.google.com": "Cloud Storage", "php": "Vulnerable Technologies",
                "api": "Vulnerable Technologies", "log": "Sensitive Files & Configs", "txt": "Sensitive Files & Configs",
                "conf": "Sensitive Files & Configs", "cnf": "Sensitive Files & Configs", "ini": "Sensitive Files & Configs",
                "env": "Credentials & Keys", "sh": "Sensitive Files & Configs", "bak": "Backup & Old Versions",
                "backup": "Backup & Old Versions", "swp": "Backup & Old Versions", "old": "Backup & Old Versions",
                "~": "Backup & Old Versions", "git": "Code Repositories / Source", "svn": "Code Repositories / Source",
                "htpasswd": "Credentials & Keys", "htaccess": "Sensitive Files & Configs", "json": "Sensitive Files & Configs",
                "conf": "Sensitive Files & Configs", "env": "Credentials & Keys", "cgi": "Vulnerable Technologies",
                "bin": "Vulnerable Technologies", "etc": "Vulnerable Technologies", "root": "Vulnerable Technologies",
                "sql": "Database Dumps", "backup": "Backup & Old Versions", "admin": "Admin Panels & Dashboards",
                "php": "Vulnerable Technologies", "error": "Information Disclosure", "exception": "Information Disclosure",
                "failure": "Information Disclosure", "server at": "Information Disclosure", "exception": "Information Disclosure",
                "database error": "Information Disclosure", "SQL syntax": "Information Disclosure", "undefined index": "Information Disclosure",
                "unhandled exception": "Information Disclosure", "stack trace": "Information Disclosure", "q=": "Vulnerable Technologies",
                "s=": "Vulnerable Technologies", "search=": "Vulnerable Technologies", "query=": "Vulnerable Technologies",
                "keyword=": "Vulnerable Technologies", "lang=": "Vulnerable Technologies", "url=": "Vulnerable Technologies",
                "return=": "Vulnerable Technologies", "next=": "Vulnerable Technologies", "redirect=": "Vulnerable Technologies",
                "redir=": "Vulnerable Technologies", "ret=": "Vulnerable Technologies", "r2=": "Vulnerable Technologies",
                "page=": "Vulnerable Technologies", "id=": "Vulnerable Technologies", "pid=": "Vulnerable Technologies",
                "category=": "Vulnerable Technologies", "cat=": "Vulnerable Technologies", "action=": "Vulnerable Technologies",
                "sid=": "Vulnerable Technologies", "dir=": "Vulnerable Technologies", "http": "Vulnerable Technologies",
                "url=": "Vulnerable Technologies", "path=": "Vulnerable Technologies", "dest=": "Vulnerable Technologies",
                "html=": "Vulnerable Technologies", "data=": "Vulnerable Technologies", "domain=": "Vulnerable Technologies",
                "page=": "Vulnerable Technologies", "include": "Vulnerable Technologies", "dir": "Vulnerable Technologies",
                "detail=": "Vulnerable Technologies", "file=": "Vulnerable Technologies", "folder=": "Vulnerable Technologies",
                "inc=": "Vulnerable Technologies", "locate=": "Vulnerable Technologies", "doc=": "Vulnerable Technologies",
                "conf=": "Vulnerable Technologies", "cmd": "Vulnerable Technologies", "exec=": "Vulnerable Technologies",
                "query=": "Vulnerable Technologies", "code=": "Vulnerable Technologies", "do=": "Vulnerable Technologies",
                "run=": "Vulnerable Technologies", "read=": "Vulnerable Technologies", "ping=": "Vulnerable Technologies",
                "choose file": "Vulnerable Technologies", "select file": "Vulnerable Technologies", "upload PDF": "Vulnerable Technologies",
                "apidocs": "Vulnerable Technologies", "api-docs": "Vulnerable Technologies", "swagger": "Vulnerable Technologies",
                "api-explorer": "Vulnerable Technologies", "redoc": "Vulnerable Technologies", "openapi": "Vulnerable Technologies",
                "Swagger UI": "Vulnerable Technologies", "login": "Login Pages / Panels", "signin": "Login Pages / Panels",
                "login": "Login Pages / Panels", "signin": "Login Pages / Panels", "secure": "Login Pages / Panels",
                "test": "Vulnerable Technologies", "env": "Credentials & Keys", "dev": "Vulnerable Technologies",
                "staging": "Vulnerable Technologies", "sandbox": "Vulnerable Technologies", "debug": "Information Disclosure",
                "temp": "Backup & Old Versions", "internal": "Sensitive Files & Configs", "demo": "Vulnerable Technologies",
                "txt": "Sensitive Files & Configs", "pdf": "Sensitive Files & Configs", "xml": "Sensitive Files & Configs",
                "xls": "Sensitive Files & Configs", "xlsx": "Sensitive Files & Configs", "ppt": "Sensitive Files & Configs",
                "pptx": "Sensitive Files & Configs", "doc": "Sensitive Files & Configs", "docx": "Sensitive Files & Configs",
                "confidential": "Sensitive Files & Configs", "Not for Public Release": "Sensitive Files & Configs",
                "internal use only": "Sensitive Files & Configs", "do not distribute": "Sensitive Files & Configs",
                "email=": "Sensitive Files & Configs", "phone=": "Sensitive Files & Configs", "name=": "Sensitive Files & Configs",
                "user=": "Sensitive Files & Configs", "/content/usergenerated": "Vulnerable Technologies", "/content/dam": "Vulnerable Technologies",
                "/jcr:content": "Vulnerable Technologies", "/libs/granite": "Vulnerable Technologies", "/etc/clientlibs": "Vulnerable Technologies",
                "/content/geometrixx": "Vulnerable Technologies", "/bin/wcm": "Vulnerable Technologies", "crx/de": "Vulnerable Technologies",
                "reports": "Information Disclosure", "groups.google.com": "Information Disclosure", "pastebin.com": "Code Repositories / Source",
                "jsfiddle.net": "Code Repositories / Source", "codebeautify.org": "Code Repositories / Source", "codepen.io": "Code Repositories / Source",
                "s3.amazonaws.com": "Cloud Storage", "blob.core.windows.net": "Cloud Storage", "googleapis.com": "Cloud Storage",
                "drive.google.com": "Cloud Storage", "dev.azure.com": "Cloud Storage", "onedrive.live.com": "Cloud Storage",
                "digitaloceanspaces.com": "Cloud Storage", "sharepoint.com": "Cloud Storage", "s3-external-1.amazonaws.com": "Cloud Storage",
                "s3.dualstack.us-east-1.amazonaws.com": "Cloud Storage", "dropbox.com": "Cloud Storage", "docs.google.com": "Cloud Storage"
            }
            intent_category = "Misc Exploitable Data"
            for key, cat in advanced_intent_mapping.items():
                if key in dork_data["name"].lower() or key in dork_data["pattern"].lower():
                    intent_category = cat
                    break
            dorks.append(Dork(
                category="Medium",
                intent_category=intent_category,
                name=dork_data["name"],
                dork=dork_data["pattern"],
                owasp=dork_data["owasp"],
                notes=dork_data["notes"],
                example_usage=dork_data["pattern"],
                tags=dork_data.get("tags", [])
            ))

    return dorks

# === Docs Rendering ===
def render_markdown_file(path: str) -> str:
    if not os.path.exists(path):
        return "<h1>Not Found</h1><p>Document not found.</p>"
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    if markdown is None:
        # Fallback: preformat text
        safe = content.replace("<", "&lt;").replace(">", "&gt;")
        return f"<pre style=\"white-space:pre-wrap\">{safe}</pre>"
    html = markdown.markdown(content, extensions=["extra", "toc", "tables", "fenced_code"])  # type: ignore
    return html

def wrap_docs_html(title: str, body_html: str) -> str:
    return f"""
<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>{title} • DorkIQ</title>
  <link rel=\"stylesheet\" href=\"/styles.css\" />
  <style>
    .docs-container {{ max-width: 900px; margin: 40px auto; padding: 0 16px; }}
    .docs-card {{ background: var(--bg-card); border: 1px solid var(--border-primary); border-radius: var(--radius-xl); padding: 32px; }}
    .docs-card h1, .docs-card h2, .docs-card h3 {{ margin: 16px 0; }}
    .docs-card pre {{ background: var(--bg-secondary); padding: 12px; border-radius: 8px; overflow-x: auto; border: 1px solid var(--border-primary); }}
    .docs-card code {{ font-family: var(--font-mono); }}
    .docs-card a {{ color: var(--accent-primary); text-decoration: none; }}
    .docs-card a:hover {{ text-decoration: underline; }}
  </style>
  </head>
<body>
  <div class=\"docs-container\"> 
    <div class=\"docs-card\">{body_html}</div>
  </div>
</body>
</html>
"""

@app.get("/readme", response_class=HTMLResponse)
async def readme_page():
    body = render_markdown_file("README.md")
    return wrap_docs_html("README", body)

@app.get("/docs/{name}", response_class=HTMLResponse)
async def docs_dynamic(name: str):
    filename = name.upper() + ".md"
    if name.lower() == "readme":
        filename = "README.md"
    path = os.path.join(os.getcwd(), filename)
    body = render_markdown_file(path)
    return wrap_docs_html(filename, body)

# === Static File Serving ===
@app.get("/", response_class=HTMLResponse)
async def serve_index():
    """Serve the main HTML file"""
    return FileResponse("index.html")

@app.get("/styles.css")
async def serve_styles():
    """Serve the CSS file"""
    return FileResponse("styles.css", media_type="text/css")

@app.get("/script.js")
async def serve_script():
    """Serve the JavaScript file"""
    return FileResponse("script.js", media_type="application/javascript")

# === API Endpoints ===
@app.post("/generate-dorks", response_model=List[Dork])
async def generate_dorks_endpoint(request: DorkRequest):
    """Generate Google Dorks for a given domain"""
    return generate_dorks(
        request.domain, 
        request.industry, 
        request.tld, 
        request.include_subdomains,
        request.vulnerability_category,
        request.advanced_mode
    )

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "message": "DorkIQ API is running"}

# === HEAD Handlers for Uptime Monitors ===
from fastapi import Response

@app.head("/", include_in_schema=False)
async def root_head():
    return Response(status_code=200)

@app.head("/api/health", include_in_schema=False)
async def health_head():
    return Response(status_code=200)



# === Run server ===
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    host = os.environ.get("HOST", "0.0.0.0")
    debug = os.environ.get("DEBUG", "false").lower() == "true"
    
    uvicorn.run(
        "app:app", 
        host=host, 
        port=port, 
        reload=debug,
        access_log=True,
        log_level="info"
    )

import requests
from bs4 import BeautifulSoup
import ssl
import socket
import dns.resolver
import whois
import concurrent.futures
import os

R = "\033[31m"
Y = "\033[33m"
W = "\033[0m"

def banner():
    print(f"""
\033[91m==================================================
.___      _____      __________          
|   | _____/ ____\\____\\______   \\__  _  ______ 
|   |/     \\  __\\/  _ \\|    ___/\\ \\/ \\/ /      \\ 
|   |  |  \\  | (  <_> )  |       \\  /   /  |  \\
|___|___|  /__|  \\____/|____|        \\/\\_/|___|  /
        \\/                                    \\/ 
==================================================\033[0m
\033[93m  Created by: fy9 | For educational purposes.\033[0m
\033[91m==================================================\033[0m
""")

def print_section(title):
    print(f"\n{R}=== {title} ==={W}")

def format_dict(d):
    lines = []
    for k, v in d.items():
        if not v:
            continue
        if isinstance(v, (list, tuple, set)):
            lines.append(f"{k}:")
            for item in v:
                if isinstance(item, dict):
                    for key2, val2 in item.items():
                        lines.append(f"  {key2}: {val2}")
                elif isinstance(item, (list, tuple, set)):
                    lines.append("  " + ", ".join(str(x) for x in item))
                else:
                    lines.append(f"  {item}")
        elif isinstance(v, dict):
            lines.append(f"{k}:")
            for key2, val2 in v.items():
                lines.append(f"  {key2}: {val2}")
        else:
            lines.append(f"{k}: {v}")
    return "\n".join(lines)

def get_site_info(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        headers = {"User-Agent": "Mozilla/5.0 (compatible; Bot/1.0)"}
        r = requests.get(url, timeout=10, headers=headers)
        soup = BeautifulSoup(r.text, "html.parser")
        metas = {meta.attrs['name']: meta.attrs['content'] 
                 for meta in soup.find_all('meta') if 'name' in meta.attrs and 'content' in meta.attrs}
        return {
            "Status Code": r.status_code,
            "Title": soup.title.string.strip() if soup.title else None,
            "Meta Tags": metas,
            "Headers": dict(r.headers)
        }
    except Exception as e:
        print(f"{R}Error fetching site info: {e}{W}")
        return None

def get_ssl_info(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    "Subject": cert.get('subject'),
                    "Issuer": cert.get('issuer'),
                    "Valid From": cert.get('notBefore'),
                    "Valid Until": cert.get('notAfter')
                }
    except Exception as e:
        print(f"{R}Error fetching SSL info: {e}{W}")
        return None

def read_wordlist(filename):
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{R}Error: The file '{filename}' was not found.{W}")
        return []

def subdomain_scan(domain, wordlist):
    found = []
    if not wordlist:
        return found
    
    resolver = dns.resolver.Resolver()

    def check_subdomain(sub):
        full_domain = f"{sub}.{domain}"
        try:
            answers = resolver.resolve(full_domain, 'A', lifetime=2)
            for rdata in answers:
                return (full_domain, rdata.address)
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(check_subdomain, wordlist)
    
    found = [res for res in results if res]
    return found

def get_dns_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception as e:
        print(f"{R}Error resolving DNS IP: {e}{W}")
        return None

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return {k: w.get(k) for k in ['domain_name', 'registrar', 'creation_date', 'expiration_date', 'emails', 'status']}
    except Exception as e:
        print(f"{R}Error fetching WHOIS info: {e}{W}")
        return None

def check_robots_sitemap(domain):
    base_url = f"http://{domain}" if not domain.startswith("http") else domain
    results = {}
    headers = {"User-Agent": "Mozilla/5.0 (compatible; Bot/1.0)"}
    try:
        r = requests.get(base_url.rstrip('/') + "/robots.txt", timeout=5, headers=headers)
        results['robots'] = r.text[:200] + "..." if r.status_code == 200 else None
    except Exception as e:
        print(f"{R}Error fetching robots.txt: {e}{W}")
        results['robots'] = None
    try:
        r = requests.get(base_url.rstrip('/') + "/sitemap.xml", timeout=5, headers=headers)
        results['sitemap'] = r.text[:200] + "..." if r.status_code == 200 else None
    except Exception as e:
        print(f"{R}Error fetching sitemap.xml: {e}{W}")
        results['sitemap'] = None
    return results

def simple_port_scan_threaded(ip, ports=[80, 443, 21, 22, 25, 3306]):
    open_ports = []
    if not ip:
        return open_ports

    def scan_port(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            if sock.connect_ex((ip, port)) == 0:
                return port
        except Exception:
            return None
        finally:
            sock.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(scan_port, ports)
    open_ports = [port for port in results if port]
    return open_ports

def test_xss(url):
    payload = "<script>alert(1)</script>"
    if "?" not in url:
        url += "?"
    try:
        r = requests.get(f"{url}&testparam={payload}", timeout=10)
        return payload in r.text
    except Exception as e:
        print(f"{R}Error testing XSS: {e}{W}")
        return False

def test_sql_injection(url):
    payloads = ["'", "' OR '1'='1", '" OR "1"="1']
    if "?" not in url:
        url += "?"
    try:
        for p in payloads:
            r = requests.get(f"{url}&testparam={p}", timeout=10)
            errors = ["You have an error in your SQL syntax", "Warning: mysql", "Unclosed quotation mark"]
            if any(e.lower() in r.text.lower() for e in errors):
                return True
    except Exception as e:
        print(f"{R}Error testing SQL Injection: {e}{W}")
    return False

def main():
    banner()
    domain = input("Enter the target site URL (e.g., example.com): ").strip()

    report = []

    info = get_site_info(domain)
    if info:
        print_section("General Site Information")
        report.append("=== General Site Information ===")
        report.append(format_dict(info))
        print(format_dict(info))
        if info.get("Meta Tags"):
            report.append("Meta Tags:\n" + format_dict(info["Meta Tags"]))
            print("Meta Tags:")
            print(format_dict(info["Meta Tags"]))

    ssl_info = get_ssl_info(domain)
    if ssl_info:
        print_section("SSL Certificate")
        report.append("=== SSL Certificate ===")
        report.append(format_dict(ssl_info))
        print(format_dict(ssl_info))

    ip = get_dns_ip(domain)
    if ip:
        print_section("DNS & IP")
        report.append("=== DNS & IP ===")
        report.append(f"IP: {ip}")
        print(f"IP: {ip}")

    # Subdomain listesini dosyadan oku
    wordlist = read_wordlist("subdomains.txt")
    
    # Subdomain taraması yapılırken mesajı göster
    print_section("Subdomain Scanning")
    print(f"{Y}Subdomain scanning is in progress, please wait...{W}")
    
    subs = subdomain_scan(domain, wordlist)
    if subs:
        print(f"{R}=== Found Subdomains ==={W}")
        report.append("=== Found Subdomains ===")
        for s, ip_addr in subs:
            report.append(f"{s} -> {ip_addr}")
            print(f"{s} -> {ip_addr}")
    else:
        print(f"{Y}No subdomains found or 'subdomains.txt' file is empty/missing.{W}")

    whois_info = get_whois_info(domain)
    if whois_info:
        print_section("Whois Information")
        report.append("=== Whois Information ===")
        report.append(format_dict(whois_info))
        print(format_dict(whois_info))

    rs = check_robots_sitemap(domain)
    if rs.get('robots'):
        print_section("robots.txt")
        report.append("=== robots.txt ===")
        report.append(rs['robots'])
        print(rs['robots'])
    if rs.get('sitemap'):
        print_section("sitemap.xml")
        report.append("=== sitemap.xml ===")
        report.append(rs['sitemap'])
        print(rs['sitemap'])

    open_ports = simple_port_scan_threaded(ip)
    if open_ports:
        print_section("Open Ports")
        report.append("=== Open Ports ===")
        for port in open_ports:
            report.append(f"Port {port}")
            print(f"Port {port}")

    xss_vuln = test_xss(domain if domain.startswith("http") else "http://" + domain)
    print_section("XSS Vulnerability")
    report.append("=== XSS Vulnerability ===")
    report.append("Detected" if xss_vuln else "Not Detected")
    print("Detected" if xss_vuln else "Not Detected")

    sql_vuln = test_sql_injection(domain if domain.startswith("http") else "http://" + domain)
    print_section("SQL Injection Vulnerability")
    report.append("=== SQL Injection Vulnerability ===")
    report.append("Detected" if sql_vuln else "Not Detected")
    print("Detected" if sql_vuln else "Not Detected")

    choice = input("\nDo you want to save the results? (Y/N): ").strip().lower()
    if choice == "y":
        filename = f"{domain.replace('http://', '').replace('https://', '').replace('/', '_')}.txt"
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(report))
        print(f"Results saved to '{filename}'.")

    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
subcheck.py - simple subdomain checker

Usage:
    python3 subcheck.py -d example.com -w wordlist.txt -t 50 -o found.csv

Requirements:
    pip install requests
"""

import argparse
import concurrent.futures
import csv
import random
import socket
import sys
import time
from typing import Optional, Tuple

import requests

# ---------------------------
# helper functions
# ---------------------------

def resolve_host(hostname: str, timeout: float = 5.0) -> Optional[str]:
    """Try to resolve hostname to an IP. Returns IP string or None."""
    try:
        # socket.gethostbyname may block but quick; wrap caller in ThreadPoolExecutor
        ip = socket.gethostbyname(hostname)
        return ip
    except Exception:
        return None

def http_check(url: str, timeout: float = 7.0) -> Tuple[Optional[int], Optional[str]]:
    """
    Try to GET url. Returns (status_code, final_url) or (None, None) on failure.
    """
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True, headers={
            "User-Agent": "subcheck/1.0"
        })
        return resp.status_code, resp.url
    except Exception:
        return None, None

def probe_subdomain(sub: str, domain: str, try_https_first: bool = True, dns_timeout: float = 5.0, http_timeout: float = 7.0):
    """
    Check single subdomain: resolve and try HTTP(S).
    Returns dict with results.
    """
    fqdn = f"{sub}.{domain}".strip(".")
    ip = resolve_host(fqdn, timeout=dns_timeout)
    status = None
    final_url = None
    scheme_used = None

    if ip:
        # try https first if requested
        schemes = ["https", "http"] if try_https_first else ["http", "https"]
        for s in schemes:
            url = f"{s}://{fqdn}"
            sc, fu = http_check(url, timeout=http_timeout)
            if sc is not None:
                status = sc
                final_url = fu
                scheme_used = s
                break

    return {
        "subdomain": fqdn,
        "ip": ip,
        "status": status,
        "final_url": final_url,
        "scheme": scheme_used
    }

# ---------------------------
# main CLI + logic
# ---------------------------

def detect_wildcard(domain: str) -> bool:
    """Detect wildcard DNS by resolving a random non-existent subdomain and checking for an IP."""
    rnd = f"random-{int(time.time())}-{random.randint(10000,99999)}"
    fqdn = f"{rnd}.{domain}"
    ip = resolve_host(fqdn)
    return ip is not None

def load_wordlist(path: str):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    return lines

def write_csv(path: str, rows, fieldnames=None):
    if fieldnames is None:
        fieldnames = ["subdomain", "ip", "status", "scheme", "final_url"]
    with open(path, "w", newline="", encoding="utf-8") as csvf:
        w = csv.DictWriter(csvf, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({k: (r.get(k) or "") for k in fieldnames})

def main():
    parser = argparse.ArgumentParser(description="Simple Subdomain Checker")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (example.com)")
    parser.add_argument("-w", "--wordlist", required=True, help="Wordlist file (one sub per line)")
    parser.add_argument("-t", "--threads", type=int, default=30, help="Number of worker threads")
    parser.add_argument("-o", "--output", default="subdomains_found.csv", help="CSV output file")
    parser.add_argument("--no-https", action="store_true", help="Don't try HTTPS first (only try HTTP then HTTPS)")
    parser.add_argument("--timeout-http", type=float, default=7.0, help="HTTP request timeout seconds")
    parser.add_argument("--timeout-dns", type=float, default=5.0, help="DNS resolution timeout seconds (internal)")
    args = parser.parse_args()

    domain = args.domain.strip().lower()
    wordlist = args.wordlist
    threads = max(1, args.threads)
    out_file = args.output
    try_https_first = not args.no_https

    try:
        subs = load_wordlist(wordlist)
    except FileNotFoundError:
        print(f"[!] Wordlist file not found: {wordlist}", file=sys.stderr)
        sys.exit(2)

    if not subs:
        print("[!] Wordlist is empty.", file=sys.stderr)
        sys.exit(2)

    # wildcard detection
    print("[*] Checking wildcard DNS...")
    has_wildcard = detect_wildcard(domain)
    if has_wildcard:
        print("[!] Wildcard DNS detected: many random subdomains resolve to an IP. Results may include false positives.")
    else:
        print("[+] No wildcard detected (likely)")

    total = len(subs)
    print(f"[*] Starting checks: {total} subdomains (threads={threads})")

    results = []
    started = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        # map futures
        future_to_sub = {
            executor.submit(probe_subdomain, sub, domain, try_https_first, args.timeout_dns, args.timeout_http): sub for sub in subs
        }

        done_count = 0
        for fut in concurrent.futures.as_completed(future_to_sub):
            sub = future_to_sub[fut]
            done_count += 1
            try:
                res = fut.result()
            except Exception as e:
                print(f"[!] Error checking {sub}.{domain}: {e}")
                continue

            # print live info
            if res["ip"]:
                print(f"[FOUND] {res['subdomain']:30s} IP={res['ip']:15s} status={str(res['status']) if res['status'] else '-'} scheme={res['scheme'] or '-'}")
                results.append(res)
            else:
                # Uncomment next line to see negative hits (will be verbose)
                # print(f"[MISS ] {sub}.{domain}")
                pass

            # progress simple
            if done_count % 50 == 0 or done_count == total:
                elapsed = time.time() - started
                print(f"    checked {done_count}/{total} - elapsed {elapsed:.1f}s")

    # write CSV
    if results:
        write_csv(out_file, results)
        print(f"[*] Done. Found {len(results)} resolving subdomains. Saved to: {out_file}")
    else:
        print("[*] Done. No resolving subdomains found.")

if __name__ == "__main__":
    main()

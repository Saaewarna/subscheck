#!/usr/bin/env python3
"""
subenum_auto_final.py - automatic subdomain enumeration (no wordlist needed)

Sources & flow:
- Fetch candidates from Certificate Transparency (crt.sh) public endpoint
- Optional AXFR (zone transfer) attempt on nameservers
- Optional mutation/expansion of discovered hosts
- Resolve A and CNAME (dnspython)
- Optional HTTP(S) probe with retry/backoff + UA rotation
- Concurrent execution
- Robust CSV writer (quotes + stringify) to prevent blank/shifted columns in Excel

Install:
    pip install requests dnspython

Examples:
    python3 subenum_auto_final.py -d example.com
    python3 subenum_auto_final.py -d example.com --no-http --expand -o found.csv
    python3 subenum_auto_final.py -d example.com --axfr -t 30
"""
import argparse
import concurrent.futures
import csv
import json
import random
import re
import sys
import time
from typing import Optional, List, Dict, Set

import requests
import dns.resolver
import dns.query
import dns.zone
import dns.exception

# -----------------------
# config
# -----------------------
UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    "curl/7.88.1",
    "python-requests/2.31.0"
]

DEFAULT_HEADERS = {"Accept": "*/*"}

resolver = dns.resolver.Resolver()

# -----------------------
# utilities
# -----------------------
def fetch_crtsh(domain: str, timeout: float = 15.0) -> Set[str]:
    """
    Query crt.sh for certificates related to %.domain and return unique hostnames.
    Uses JSON output; falls back to regex extraction when JSON is malformed.
    """
    base = "https://crt.sh/"
    urls = [
        f"{base}?q=%25.{domain}&output=json",
        f"{base}?q={domain}&output=json",
    ]
    hosts:set[str] = set()
    for url in urls:
        try:
            r = requests.get(url, timeout=timeout, headers={"User-Agent": random.choice(UA_LIST)})
            if r.status_code != 200 or not r.text:
                continue
            data = r.text
            try:
                entries = json.loads(data)
                for e in entries:
                    nv = e.get("name_value")
                    if not nv:
                        continue
                    for part in nv.split("\n"):
                        part = part.strip().lstrip("*.")
                        if part.endswith("."):
                            part = part[:-1]
                        if part:
                            hosts.add(part.lower())
            except json.JSONDecodeError:
                # fallback to regex when JSON is malformed
                names = set(re.findall(r'"name_value"\s*:\s*"([^"]+)"', data))
                for n in names:
                    for line in n.replace("\\n", "\n").split("\n"):
                        line = line.strip().lstrip("*.")
                        if line.endswith("."):
                            line = line[:-1]
                        if line:
                            hosts.add(line.lower())
        except Exception:
            continue
    return hosts

def attempt_axfr(domain: str, timeout: float = 5.0) -> Set[str]:
    """
    Attempt zone transfer (AXFR) for each NS. Return set of hostnames if any.
    """
    found = set()
    try:
        answers = resolver.resolve(domain, "NS", lifetime=timeout)
        ns_hosts = [str(rdata.target).rstrip(".") for rdata in answers]
    except Exception:
        ns_hosts = []
    for ns in ns_hosts:
        try:
            try:
                ns_ip = resolver.resolve(ns, "A", lifetime=timeout)[0].to_text()
            except Exception:
                ns_ip = None
            if not ns_ip:
                continue
            try:
                z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=timeout))
                if z:
                    for name, node in z.nodes.items():
                        fqdn = f"{name}.{domain}".rstrip(".")
                        found.add(fqdn.lower())
            except dns.exception.DNSException:
                pass
        except Exception:
            continue
    return found

def resolve_a(host: str, timeout: float = 3.0) -> Optional[str]:
    try:
        ans = resolver.resolve(host, "A", lifetime=timeout)
        return ans[0].to_text()
    except Exception:
        return None

def resolve_cname(host: str, timeout: float = 2.0) -> Optional[str]:
    try:
        ans = resolver.resolve(host, "CNAME", lifetime=timeout)
        return str(ans[0].target).rstrip(".")
    except Exception:
        return None

def requests_with_backoff(url: str, timeout: float = 7.0, tries: int = 3, backoff: float = 0.9):
    for i in range(tries):
        try:
            r = requests.get(url, timeout=timeout, headers={"User-Agent": random.choice(UA_LIST)}, allow_redirects=True)
            if r.status_code == 429 or 500 <= r.status_code < 600:
                time.sleep(backoff * (2 ** i) + random.random())
                continue
            return r
        except requests.RequestException:
            time.sleep(backoff * (2 ** i) + random.random())
    return None

# -----------------------
# mutation / expansion
# -----------------------
def expand_hosts_basic(hosts: Set[str], domain: str) -> Set[str]:
    suffixes = ["-dev","-test","-staging","-stg","-uat","-old","-backup","-01","-02"]
    prefixes = ["dev-","test-","stg-"]
    new = set()
    for h in hosts:
        if not (h == domain or h.endswith("." + domain)):
            continue
        label = h[:-len(domain)].rstrip(".")
        if not label:
            continue
        parts = label.split(".")
        base = parts[0]
        for s in suffixes:
            new.add(f"{base}{s}.{domain}")
        for p in prefixes:
            new.add(f"{p}{base}.{domain}")
        for n in ["1","2","01","02"]:
            new.add(f"{base}{n}.{domain}")
    return new

# -----------------------
# main worker
# -----------------------
def probe_host(host: str, do_http: bool, timeout_dns: float, timeout_http: float, min_delay: float = 0.0, max_delay: float = 0.0) -> Dict:
    if max_delay and max_delay >= min_delay and min_delay > 0:
        time.sleep(random.uniform(min_delay, max_delay))
    res = {"host": host, "ip": None, "cname": None, "status": None, "scheme": None, "final_url": None, "notes": ""}
    ip = resolve_a(host, timeout=timeout_dns)
    if not ip:
        res["notes"] = "no-a"
        return res
    res["ip"] = ip
    cname = resolve_cname(host, timeout=1.0)
    if cname:
        res["cname"] = cname
    if not do_http:
        res["notes"] = "dns-only"
        return res
    # try https then http
    for scheme in ["https","http"]:
        url = f"{scheme}://{host}"
        r = requests_with_backoff(url, timeout=timeout_http)
        if r is not None:
            res["status"] = r.status_code
            res["final_url"] = r.url
            res["scheme"] = scheme
            if r.status_code in (403,406):
                res["notes"] += "waf;"
            return res
    res["notes"] += "no-http"
    return res

# -----------------------
# runner
# -----------------------
def main():
    parser = argparse.ArgumentParser(description="Auto subdomain enumerator (crt.sh + axfr + expand)")
    parser.add_argument("-d", "--domain", required=True, help="target domain (example.com)")
    parser.add_argument("-o", "--out", default="subenum_results.csv", help="csv output file")
    parser.add_argument("--no-http", action="store_true", help="skip HTTP probing (DNS-only)")
    parser.add_argument("--axfr", action="store_true", help="try zone transfer on nameservers")
    parser.add_argument("--expand", action="store_true", help="auto expand/mutate discovered hosts")
    parser.add_argument("-t", "--threads", type=int, default=20, help="concurrency")
    parser.add_argument("--timeout-dns", type=float, default=3.0)
    parser.add_argument("--timeout-http", type=float, default=6.0)
    parser.add_argument("--min-delay", type=float, default=0.0, help="min jitter between probes")
    parser.add_argument("--max-delay", type=float, default=0.0, help="max jitter between probes")
    args = parser.parse_args()

    domain = args.domain.strip().lower()

    print(f"[*] Gathering candidates for {domain} via crt.sh...")
    crt_hosts = fetch_crtsh(domain)
    print(f"[*] crt.sh returned {len(crt_hosts)} candidate names (dedup).")

    all_hosts: Set[str] = set()
    for h in crt_hosts:
        if h == domain or h.endswith("." + domain):
            all_hosts.add(h)

    if args.axfr:
        print("[*] Attempting AXFR against domain nameservers (may be silent if none allow it)...")
        axfr_hosts = attempt_axfr(domain)
        if axfr_hosts:
            print(f"[+] AXFR yielded {len(axfr_hosts)} names.")
            for h in axfr_hosts:
                if h == domain or h.endswith("." + domain):
                    all_hosts.add(h)
        else:
            print("[-] AXFR did not return useful names (likely not allowed).")

    print(f"[*] Initial candidate count: {len(all_hosts)}")

    if args.expand:
        print("[*] Expanding candidates using basic mutation rules...")
        extra = expand_hosts_basic(all_hosts, domain)
        print(f"[*] Mutations generated: {len(extra)}")
        all_hosts |= extra
        print(f"[*] Total candidates after expand: {len(all_hosts)}")

    if not all_hosts:
        print("[!] No candidates found. Try running without filtering or enable --expand/--axfr.")
        sys.exit(0)

    hosts_list = sorted(all_hosts)
    results = []
    print(f"[*] Probing {len(hosts_list)} hosts (dns{' + http' if not args.no_http else ''}) with {args.threads} threads")
    started = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.threads)) as exe:
        future_map = {
            exe.submit(probe_host, h, not args.no_http, args.timeout_dns, args.timeout_http, args.min_delay, args.max_delay): h
            for h in hosts_list
        }
        done = 0
        for fut in concurrent.futures.as_completed(future_map):
            h = future_map[fut]
            done += 1
            try:
                r = fut.result()
            except Exception as e:
                print(f"[!] Error probing {h}: {e}")
                continue
            if r.get("ip"):
                # always stringify here for consistent printing
                status_str = str(r['status']) if r['status'] is not None else "-"
                print(f"[FOUND] {r['host']:40s} IP={r['ip']:15s} status={status_str:4s} notes={r.get('notes','')}")
                results.append(r)
            if done % 50 == 0 or done == len(hosts_list):
                elapsed = time.time() - started
                print(f"    progress {done}/{len(hosts_list)} - elapsed {elapsed:.1f}s")

    # write CSV (robust: stringify + quoting)
    fieldnames = ["host", "ip", "cname", "status", "scheme", "final_url", "notes"]
    with open(args.out, "w", newline="", encoding="utf-8") as csvf:
        w = csv.DictWriter(csvf, fieldnames=fieldnames, quoting=csv.QUOTE_MINIMAL)
        w.writeheader()
        for row in results:
            out = {}
            for k in fieldnames:
                v = row.get(k, "")
                out[k] = "" if v is None else str(v)
            w.writerow(out)

    print(f"[*] Done. {len(results)} hosts saved to {args.out}")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
xss_with_list_progress_detect_print.py

Same behavior as the progress scanner, but prints every detected payload
line-by-line as soon as it's found, and appends them to detected_payloads.txt.

Usage:
  python xss_with_list_progress_detect_print.py https://target.example/page payloads.txt
"""
import sys, asyncio, time, json, os
from datetime import datetime
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse, quote_plus
import aiohttp
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright
from tqdm import tqdm

# Config
CONCURRENCY = 8
TIMEOUT = 15
USER_AGENT = "xss-list-scanner/0.3"
TOKEN_PREFIX = "XSS_TOKEN_"
OUTPUT_DETECTIONS = "detected_payloads.txt"

# Helpers
def read_payloads(path):
    with open(path, "r", encoding="utf-8") as f:
        lines = [ln.rstrip("\n") for ln in f]
    return [ln for ln in lines if ln and not ln.startswith("#")]

def uniq_token(i):
    # slightly more entropy so tokens are unique across near-simultaneous runs
    return TOKEN_PREFIX + str(int(time.time() * 1000))[-8:] + "_" + str(i)

def inject_query(url, param, value):
    p = urlparse(url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q[param] = value
    new_q = urlencode(q, doseq=True)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, p.fragment))

def html_escape(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;")

async def fetch(session, method, url, **kwargs):
    try:
        async with session.request(method, url, timeout=TIMEOUT, **kwargs) as r:
            text = await r.text(errors="ignore")
            return r.status, text, str(r.url)
    except Exception as e:
        return None, f"ERROR: {e}", url

async def dom_check(url):
    """Return True if window.__xss_marker === true after navigation."""
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch()
            ctx = await browser.new_context()
            page = await ctx.new_page()
            await page.goto(url, timeout=12000)
            await asyncio.sleep(1.0)
            res = await page.evaluate("() => (window.__xss_marker === true ? true : false)")
            await browser.close()
            return bool(res)
    except Exception:
        return False

def format_detection_line(d):
    """Return two-line string for human reading: meta-line + payload line."""
    ts = datetime.utcfromtimestamp(int(time.time())).isoformat() + "Z"
    meta = f"[{ts}] {d['type'].upper()} | {d['method']} | param={d['param']} | evidence={d.get('evidence','')} | url={d['url']}"
    payload_line = f"PAYLOAD: {d['payload']}"
    return meta + "\n" + payload_line + "\n" + ("-"*60)

async def append_and_print_detection(d, lock):
    """Thread-safe write to file and print using tqdm.write (keeps progress bar valid)."""
    line = format_detection_line(d)
    async with lock:
        # print a clean line without breaking the tqdm bar
        tqdm.write(line)
        # append to file
        with open(OUTPUT_DETECTIONS, "a", encoding="utf-8") as f:
            f.write(line + "\n")

# Core scanning with immediate detection printing
async def scan(url, payloads):
    results = []
    # clear or create detections file
    open(OUTPUT_DETECTIONS, "w").close()
    headers = {"User-Agent": USER_AGENT}
    connector = aiohttp.TCPConnector(limit_per_host=CONCURRENCY)
    start_time = time.time()

    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        st, home, final = await fetch(session, "GET", url)
        if st is None:
            print("Failed to fetch target:", home)
            return results

        # collect params from query
        parsed = urlparse(final)
        query_params = [k for k, _ in parse_qsl(parsed.query)]
        # collect form param names
        soup = BeautifulSoup(home, "lxml")
        forms = soup.find_all("form")
        form_fields = set()
        for f in forms:
            for inp in f.find_all(["input","textarea","select"]):
                nm = inp.get("name")
                if nm:
                    form_fields.add(nm)

        if not query_params:
            query_params = ["q","search","id","page","s"]

        # Pre-calc total tests (approx)
        total_get_tests = len(payloads) * len(query_params)
        total_post_tests = 0
        for f in forms:
            names = [inp.get("name") for inp in f.find_all(["input","textarea","select"]) if inp.get("name")]
            total_post_tests += len(names) * len(payloads)
        total_tests = total_get_tests + total_post_tests

        pbar = tqdm(total=total_tests, desc="Payload tests", unit="test", ncols=100)
        attempted = 0
        positives = 0
        sem = asyncio.Semaphore(CONCURRENCY)
        lock = asyncio.Lock()  # for printing/writing

        async def handle_detection(d):
            nonlocal positives, results
            results.append(d)
            positives += 1
            await append_and_print_detection(d, lock)

        async def test_get(param, payload, idx):
            nonlocal attempted
            async with sem:
                token = uniq_token(idx)
                if "PAYLOAD" in payload:
                    body_payload = payload.replace("PAYLOAD", token)
                else:
                    body_payload = payload + token
                test_url = inject_query(final, param, body_payload)
                stt, text, used = await fetch(session, "GET", test_url)
                async with lock:
                    attempted += 1
                    pbar.update(1)
                if stt is None:
                    return
                if token in text:
                    d = {"type":"reflected","param":param,"method":"GET","payload":body_payload,"evidence":"token found","url":test_url}
                    await handle_detection(d)
                    # DOM verification if marker present
                    if "window.__xss_marker" in body_payload:
                        dom = await dom_check(test_url)
                        if dom:
                            d2 = {"type":"dom-xss","param":param,"method":"GET","payload":body_payload,"evidence":"dom marker true","url":test_url}
                            await handle_detection(d2)
                    return
                # encoded checks
                if quote_plus(token) in text or html_escape(token) in text:
                    d = {"type":"possible-encoded","param":param,"method":"GET","payload":body_payload,"evidence":"encoded token seen","url":test_url}
                    await handle_detection(d)

        async def test_post(form, param, payload, idx):
            nonlocal attempted
            async with sem:
                token = uniq_token(idx)
                if "PAYLOAD" in payload:
                    body_payload = payload.replace("PAYLOAD", token)
                else:
                    body_payload = payload + token
                action = form.get("action") or final
                action_url = action if action.startswith("http") else final.rstrip("/") + "/" + action.lstrip("/")
                data = {}
                for inp in form.find_all(["input","textarea","select"]):
                    nm = inp.get("name")
                    if not nm: continue
                    data[nm] = ""
                data[param] = body_payload
                stt, text, used = await fetch(session, "POST", action_url, data=data)
                async with lock:
                    attempted += 1
                    pbar.update(1)
                if stt is None:
                    return
                if token in text:
                    d = {"type":"reflected","param":param,"method":"POST","payload":body_payload,"evidence":"token found","url":action_url}
                    await handle_detection(d)
                elif quote_plus(token) in text or html_escape(token) in text:
                    d = {"type":"possible-encoded","param":param,"method":"POST","payload":body_payload,"evidence":"encoded token seen","url":action_url}
                    await handle_detection(d)

        # Schedule tasks
        tasks = []
        for param in query_params:
            for idx, payload in enumerate(payloads):
                tasks.append(asyncio.create_task(test_get(param, payload, idx)))

        for form in forms:
            names = [inp.get("name") for inp in form.find_all(["input","textarea","select"]) if inp.get("name")]
            for param in names:
                for idx, payload in enumerate(payloads):
                    tasks.append(asyncio.create_task(test_post(form, param, payload, idx)))

        # Run tasks
        if tasks:
            await asyncio.gather(*tasks)
        pbar.close()
        duration = time.time() - start_time
        # Final summary
        print("\nScan summary:")
        print(f"  Target: {final}")
        print(f"  Payloads loaded: {len(payloads)}")
        print(f"  Total tests attempted: {attempted}/{total_tests}")
        print(f"  Positives found: {positives}")
        print(f"  Time elapsed: {duration:.1f}s")
    return results

# CLI
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python xss_with_list_progress_detect_print.py <url> <payloads.txt>")
        sys.exit(1)
    target = sys.argv[1]
    payload_file = sys.argv[2]
    payloads = read_payloads(payload_file)
    print(f"Loaded {len(payloads)} payloads.")
    res = asyncio.run(scan(target, payloads))
    # Save complete JSON report as well
    with open("xss_scan_results.json","w", encoding="utf-8") as f:
        json.dump({"target":target,"results":res,"timestamp":int(time.time())}, f, indent=2)
    print("Saved xss_scan_results.json and appended detections to", OUTPUT_DETECTIONS)

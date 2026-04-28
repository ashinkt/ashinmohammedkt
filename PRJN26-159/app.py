"""Zero-Day Scanner - Flask Backend for scanning links"""

import time
from urllib.parse import urljoin, urlparse

from flask import Flask, render_template, request
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
      "AppleWebKit/537.36 ZeroDayScanner/1.0 (Educational)")


def fetch_page(url):
    """GET the page. Returns (html, None) on success or (None, error_msg) on failure."""
    try:
        r = requests.get(url, headers={"User-Agent": UA}, timeout=10)
        r.raise_for_status()
        return r.text, None

    except requests.exceptions.MissingSchema:
        return None, (
            f"<strong>Invalid URL format.</strong> "
            f"<code>{url}</code> is not a valid web address. "
            "Make sure it starts with <code>https://</code>."
        )
    except requests.exceptions.ConnectionError:
        return None, (
            f"<strong>Could not connect to <code>{url}</code>.</strong> "
            "The site may be offline, the domain may not exist, "
            "or there may be a network issue."
        )
    except requests.exceptions.Timeout:
        return None, (
            f"<strong>Connection timed out</strong> while reaching "
            f"<code>{url}</code>. The server took too long to respond (&gt;10s)."
        )
    except requests.exceptions.HTTPError as e:
        code = e.response.status_code if e.response is not None else "?"
        return None, (
            f"<strong>HTTP {code} error</strong> returned by "
            f"<code>{url}</code>. The server rejected the request."
        )
    except requests.exceptions.RequestException as e:
        return None, f"<strong>Request failed:</strong> {e}"


def extract_links(html, base_url):
    """Parse HTML with BeautifulSoup, return list of unique absolute URLs."""
    soup  = BeautifulSoup(html, "html.parser")
    links = set()

    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        # Skip non-web links
        if href.startswith(("mailto:", "javascript:", "#", "tel:", "data:")):
            continue
        absolute = urljoin(base_url, href)
        if absolute.startswith(("http://", "https://")):
            links.add(absolute)

    return list(links)


def check_status(url, base_domain):
    """HEAD-request one URL; return a result dict with status, code, category."""
    ua_headers  = {"User-Agent": "Mozilla/5.0 ZeroDayScanner/1.0"}
    parsed      = urlparse(url)
    is_external = bool(parsed.netloc) and parsed.netloc != base_domain

    try:
        # HEAD is faster (no body); allow_redirects=False catches 3xx manually
        r    = requests.head(url, headers=ua_headers, timeout=8, allow_redirects=False)
        code = r.status_code
        # Fall back to GET if server rejects HEAD
        if code == 405:
            r    = requests.get(url, headers=ua_headers, timeout=8, allow_redirects=False)
            code = r.status_code

    except requests.exceptions.ConnectionError:
        return _result(url, 0, "Connection Error", "broken", is_external)
    except requests.exceptions.Timeout:
        return _result(url, 0, "Timeout",          "broken", is_external)
    except requests.exceptions.RequestException:
        return _result(url, 0, "Request Error",    "broken", is_external)

    # Categorise by HTTP code with descriptive labels
    if 200 <= code < 300:
        status   = f"{code} OK"
        category = "external" if is_external else "working"
    elif code == 301:
        status, category = "301 Moved Permanently",  "redirect"
    elif code == 302:
        status, category = "302 Found (Redirect)",   "redirect"
    elif code in (303, 307, 308):
        status, category = f"{code} Redirect",       "redirect"
    elif 300 <= code < 400:
        status, category = f"{code} Redirect",       "redirect"
    elif code == 400:
        status, category = "400 Bad Request",        "broken"
    elif code == 401:
        status, category = "401 Unauthorised",       "broken"
    elif code == 403:
        status, category = "403 Forbidden",          "broken"
    elif code == 404:
        status, category = "404 Page Not Found",     "broken"
    elif code == 405:
        status, category = "405 Method Not Allowed", "broken"
    elif code == 429:
        status, category = "429 Too Many Requests",  "broken"
    elif code == 500:
        status, category = "500 Internal Server Error", "broken"
    elif code == 502:
        status, category = "502 Bad Gateway",           "broken"
    elif code == 503:
        status, category = "503 Server Unavailable",    "broken"
    elif code == 504:
        status, category = "504 Gateway Timeout",       "broken"
    elif code >= 500:
        status, category = f"{code} Server Error",      "broken"
    else:
        status, category = f"{code} Unknown",           "broken"

    return _result(url, code, status, category, is_external)


def _result(url, code, status, category, is_external):
    """Build a consistent result dictionary."""
    return {
        "url":      url,
        "code":     code,
        "status":   status,
        "category": category,
        "external": is_external,
        "type":     "External" if is_external else "Internal",
    }


def scan_links(links, base_domain):
    """Check every discovered URL in parallel using 20 threads."""
    results = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_status, url, base_domain): url
                   for url in links}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                pass

    # Sort: broken first, then redirects, then by code
    priority = {"broken": 0, "redirect": 1, "external": 2, "working": 3}
    results.sort(key=lambda r: (priority.get(r["category"], 9), r["code"]))
    return results


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    target_url = request.form.get("url", "").strip()

    # Empty submission
    if not target_url:
        return _error_response(
            target_url="(none)",
            msg="<strong>No URL entered.</strong> Please go back and type a URL to scan.",
            etype="empty"
        )

    # Auto-prepend https://
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    # Validate domain
    base_domain = urlparse(target_url).netloc
    if not base_domain:
        return _error_response(
            target_url=target_url,
            msg=(f"<strong>Invalid URL:</strong> <code>{target_url}</code> has no "
                 "valid domain. Example: <code>https://books.toscrape.com</code>"),
            etype="invalid"
        )

    # Fetch page
    start      = time.time()
    html, err  = fetch_page(target_url)
    results    = []
    error      = None
    error_type = None

    if err:
        error, error_type = err, "network"
    elif not html or not html.strip():
        error = (f"<strong>Empty response</strong> from <code>{target_url}</code>. "
                 "The page loaded but returned no content to scan.")
        error_type = "empty_page"
    else:
        links = extract_links(html, target_url)
        if not links:
            error = (f"<strong>No links found</strong> on <code>{target_url}</code>. "
                     "The page has no <code>&lt;a href&gt;</code> tags, "
                     "or all links are anchors / JavaScript.")
            error_type = "no_links"
        else:
            results = scan_links(links, base_domain)

    elapsed  = round(time.time() - start, 2)
    working  = [r for r in results if r["category"] == "working"]
    broken   = [r for r in results if r["category"] == "broken"]
    redirect = [r for r in results if r["category"] == "redirect"]
    external = [r for r in results if r["category"] == "external"]

    return render_template(
        "results.html",
        target_url     = target_url,
        results        = results,
        total          = len(results),
        working_count  = len(working),
        broken_count   = len(broken),
        redirect_count = len(redirect),
        external_count = len(external),
        elapsed        = elapsed,
        error          = error,
        error_type     = error_type,
    )


def _error_response(target_url, msg, etype):
    """Shortcut: render results.html in error state with zero counts."""
    return render_template(
        "results.html",
        target_url=target_url, results=[], total=0,
        working_count=0, broken_count=0,
        redirect_count=0, external_count=0,
        elapsed=0,
        error=msg, error_type=etype,
    )


if __name__ == "__main__":
    print("\n  Zero-Day Scanner is running!")
    print("  Open your browser at:  http://127.0.0.1:5000")
    app.run(debug=True, host="0.0.0.0", port=5000)

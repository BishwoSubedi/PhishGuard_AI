import re
import socket
import urllib.parse
from typing import Dict, Any, Tuple
import requests
import tldextract
from bs4 import BeautifulSoup

# Use bundled Public Suffix List snapshot to avoid external DNS/network lookups
TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

# Financial and sensitive keywords monitored by the PhiUSIIL dataset
BANK_KEYWORDS = {"bank", "banking", "iban", "swift", "creditunion", "checking", "savings"}
PAY_KEYWORDS = {"pay", "payment", "paypal", "checkout", "billing", "invoice", "stripe", "wallet"}
CRYPTO_KEYWORDS = {"crypto", "bitcoin", "btc", "ethereum", "eth", "metamask", "binance", "coinbase", "web3"}

# High-risk deceptive lexical tokens used in phishing URLs
SUSPICIOUS_URL_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "update",
    "secure",
    "account",
    "confirm",
    "password",
    "credential",
    "unlock",
    "suspend",
    "suspended",
    "authenticate",
    "webscr",
    "banking",
    "paypal",
    "appleid",
    "microsoftonline",
    "recovery",
    "wallet",
}

# Standard frequencies of alphanumeric characters in legitimate English URLs
STANDARD_CHAR_PROBS: Dict[str, float] = {
    "e": 0.089, "a": 0.078, "o": 0.072, "i": 0.068, "t": 0.067,
    "n": 0.063, "s": 0.062, "r": 0.060, "c": 0.055, "l": 0.050,
    "m": 0.042, "d": 0.038, "u": 0.036, "p": 0.035, "h": 0.034,
    "g": 0.028, "b": 0.024, "v": 0.018, "k": 0.015, "w": 0.018,
    "y": 0.018, "f": 0.016, "z": 0.008, "x": 0.008, "j": 0.006,
    "q": 0.005, "0": 0.012, "1": 0.015, "2": 0.012, "3": 0.010,
    "4": 0.009, "5": 0.009, "6": 0.008, "7": 0.008, "8": 0.008,
    "9": 0.008,
}


def _longest_consecutive_run(text: str, char_predicate) -> int:
    """Return the maximum consecutive run length of characters matching char_predicate."""
    max_run = 0
    current_run = 0
    for ch in text:
        if char_predicate(ch):
            current_run += 1
            if current_run > max_run:
                max_run = current_run
        else:
            current_run = 0
    return max_run


def _compute_url_char_prob(url_body: str, char_probs: Dict[str, float], default_prob: float) -> float:
    """Calculate the average character probability across the URL using lookup metadata."""
    cleaned = [ch.lower() for ch in url_body if ch.isalnum()]
    if not cleaned:
        return default_prob
    lookup = char_probs if char_probs else STANDARD_CHAR_PROBS
    total = sum(lookup.get(ch, default_prob) for ch in cleaned)
    return round(total / len(cleaned), 6)


def _is_ip_address(domain: str) -> int:
    """Check whether the hostname is a raw IPv4 or IPv6 address."""
    host = domain.split(":")[0].strip("[]")
    if not host:
        return 0
    try:
        socket.inet_aton(host)
        return 1
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return 1
    except OSError:
        return 0


def extract_website_features(
    raw_url: str,
    lookup_metadata: Dict[str, Any],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Safely inspect a live URL with a 6-second timeout and extract all 55 features
    matching feature_columns.json.
    Returns:
      1. features_dict: All 55 features in exact schema format for the preprocessor.
      2. inspection_details: Human-readable telemetry for the frontend UI cards.
    """
    url = raw_url.strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme.lower()
    is_https = 1 if scheme == "https" else 0

    hostname = (parsed.hostname or "").lower()
    ext = TLD_EXTRACTOR(url)
    tld = (ext.suffix or "").lower()
    is_valid_tld = bool(tld)
    subdomain_str = ext.subdomain or ""
    sub_parts = [s for s in subdomain_str.split(".") if s]
    no_of_subdomain = len(sub_parts)

    domain_full = hostname
    domain_length = len(domain_full)
    tld_length = len(tld)
    url_length = len(url)
    is_domain_ip = _is_ip_address(domain_full)

    # Check DNS resolution to verify whether the domain actually exists on the internet
    dns_resolved = False
    if hostname:
        if is_domain_ip == 1:
            dns_resolved = True
        elif is_valid_tld:
            try:
                socket.getaddrinfo(hostname, None)
                dns_resolved = True
            except OSError:
                dns_resolved = False

    # PathLengthRatio calculation
    path_and_query = (parsed.path or "") + (("?" + parsed.query) if parsed.query else "")
    path_length_ratio = round(len(path_and_query) / url_length, 6) if url_length > 0 else 0.0

    # Obfuscation analysis (% hex encodings, @ symbols, etc.)
    obfuscated_matches = re.findall(r"%[0-9a-fA-F]{2}|@", url)
    no_of_obfuscated_char = sum(len(m) for m in obfuscated_matches)
    has_obfuscation = 1 if no_of_obfuscated_char > 0 else 0
    obfuscation_ratio = round(no_of_obfuscated_char / url_length, 6) if url_length > 0 else 0.0

    # Character counts & ratios across the URL
    no_of_letters = sum(1 for ch in url if ch.isalpha())
    letter_ratio = round(no_of_letters / url_length, 6) if url_length > 0 else 0.0

    no_of_digits = sum(1 for ch in url if ch.isdigit())
    digit_ratio = round(no_of_digits / url_length, 6) if url_length > 0 else 0.0

    no_of_equals = url.count("=")
    no_of_qmark = url.count("?")
    no_of_amp = url.count("&")

    # Special characters excluding alphanumeric and standard structural tokens
    standard_structural = set(":/.-?=&#")
    other_specials = [
        ch for ch in url if not ch.isalnum() and ch not in standard_structural
    ]
    no_of_other_special = len(other_specials)
    total_specials = sum(1 for ch in url if not ch.isalnum())
    spacial_char_ratio = round(total_specials / url_length, 6) if url_length > 0 else 0.0

    # Character continuation rate (longest run of letters + digits + symbols / url_length)
    longest_alpha = _longest_consecutive_run(url, lambda c: c.isalpha())
    longest_digit = _longest_consecutive_run(url, lambda c: c.isdigit())
    longest_sym = _longest_consecutive_run(url, lambda c: not c.isalnum())
    char_continuation_rate = (
        round(min(1.0, (longest_alpha + longest_digit + longest_sym) / url_length), 6)
        if url_length > 0
        else 0.0
    )

    # Lookup probabilities from training metadata
    tld_prob_map = lookup_metadata.get("tld_prob_map", lookup_metadata.get("tld_probabilities", {}))
    default_tld_prob = float(lookup_metadata.get("default_tld_prob", 0.0799628))
    if not is_valid_tld:
        tld_legitimate_prob = 0.0
    else:
        tld_legitimate_prob = float(
            tld_prob_map.get(
                tld,
                tld_prob_map.get(tld.split(".")[-1] if tld else "", default_tld_prob),
            )
        )

    char_prob_map = lookup_metadata.get("char_prob_map", lookup_metadata.get("char_probabilities", {}))
    default_char_prob = float(
        lookup_metadata.get("default_url_char_prob", lookup_metadata.get("default_char_prob", 0.057960182))
    )
    url_char_prob = _compute_url_char_prob(url, char_prob_map, default_char_prob)

    # Suspicious keyword analysis in URL
    url_lower = url.lower()
    url_tokens_all = set(re.findall(r"[a-z0-9]+", url_lower))
    has_suspicious_keywords = 1 if (
        url_tokens_all.intersection(SUSPICIOUS_URL_KEYWORDS)
        or any(
            pattern in url_lower
            for pattern in ("login", "signin", "verify", "secure-", "-account", "update-", "webscr", "credential")
        )
    ) else 0

    # Default HTML / HTTP fallback values in case the target site blocks or times out
    reachable = False
    http_status = None
    final_url = url
    no_of_url_redirect = 0
    no_of_self_redirect = 0
    hsts_header_present = 0
    csp_header_present = 0
    raw_headers: Dict[str, str] = {
        "strict-transport-security": "Missing",
        "content-security-policy": "Missing",
        "x-frame-options": "Missing",
        "x-content-type-options": "Missing",
    }

    line_of_code = 0
    largest_line_length = 0
    has_title = 0
    page_title = ""
    domain_title_match_score = 0.0
    url_title_match_score = 0.0
    has_favicon = 0
    robots = 0
    is_responsive = 0
    has_description = 0
    no_of_popup = 0
    no_of_iframe = 0
    has_external_form_submit = 0
    has_social_net = 0
    has_submit_button = 0
    has_hidden_fields = 0
    has_password_field = 0
    bank_flag = 0
    pay_flag = 0
    crypto_flag = 0
    has_copyright_info = 0
    no_of_image = 0
    no_of_css = 0
    no_of_js = 0
    no_of_self_ref = 0
    no_of_empty_ref = 0
    no_of_external_ref = 0

    # Safely fetch target webpage with a 6-second timeout and standard browser User-Agent headers
    headers_req = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
        "Cache-Control": "no-cache",
    }

    PARKED_INDICATORS = (
        "sedoparking",
        "parkingcrew",
        "bodis.com",
        "hugedomains",
        "afternic",
        "dan.com",
        "domain is for sale",
        "buy this domain",
        "this domain may be for sale",
        "parked free",
        "cgi-sys/defaultwebpage.cgi",
    )

    if is_valid_tld and dns_resolved:
        try:
            resp = requests.get(url, headers=headers_req, timeout=6, allow_redirects=True)
            http_status = resp.status_code
            final_url = resp.url
            html_text = resp.text or ""
            html_lower = html_text.lower()

            is_parked = any(ind in html_lower or ind in final_url.lower() for ind in PARKED_INDICATORS)
            if http_status < 400 and not is_parked and len(html_text.strip()) > 0:
                reachable = True
            else:
                reachable = False

            if final_url.lower().startswith("https://"):
                is_https = 1

            # Redirect analysis
            if resp.history:
                for hist_resp in resp.history:
                    loc = hist_resp.headers.get("Location", "")
                    if hostname and (hostname in loc.lower() or (ext.domain and ext.domain.lower() in loc.lower())):
                        no_of_self_redirect += 1
                    elif loc.startswith("/"):
                        no_of_self_redirect += 1
                    else:
                        no_of_url_redirect += 1

            # Security headers inspection
            lower_headers = {k.lower(): v for k, v in resp.headers.items()}
            raw_headers = {
                "strict-transport-security": lower_headers.get("strict-transport-security", "Missing"),
                "content-security-policy": lower_headers.get("content-security-policy", "Missing"),
                "x-frame-options": lower_headers.get("x-frame-options", "Missing"),
                "x-content-type-options": lower_headers.get("x-content-type-options", "Missing"),
            }
            hsts_header_present = 1 if "strict-transport-security" in lower_headers else 0
            csp_header_present = 1 if (
                "content-security-policy" in lower_headers
                or "content-security-policy-report-only" in lower_headers
            ) else 0

            lines = html_text.splitlines()
            line_of_code = len(lines)
            largest_line_length = max((len(line) for line in lines), default=0)

            soup = BeautifulSoup(html_text, "html.parser")

            # Title & matching scores (checks <title>, og:title, twitter:title, or primary <h1>)
            title_candidate = ""
            if soup.title and soup.title.string and soup.title.string.strip():
                title_candidate = soup.title.string.strip()
            else:
                for meta_key in ({"property": "og:title"}, {"name": "twitter:title"}, {"name": "title"}, {"name": "application-name"}):
                    meta_tag = soup.find("meta", attrs=meta_key)
                    if meta_tag and (meta_tag.get("content") or "").strip():
                        title_candidate = meta_tag["content"].strip()
                        break
                if not title_candidate:
                    h1_tag = soup.find("h1")
                    if h1_tag and h1_tag.get_text(strip=True):
                        title_candidate = h1_tag.get_text(strip=True)[:120]

            if title_candidate:
                has_title = 1
                page_title = title_candidate
                title_tokens = {w.lower() for w in re.findall(r"[a-zA-Z0-9]+", page_title) if len(w) > 2}
                domain_tokens = {w.lower() for w in re.findall(r"[a-zA-Z0-9]+", ext.domain or hostname) if len(w) > 2}
                url_tokens = {w.lower() for w in re.findall(r"[a-zA-Z0-9]+", url) if len(w) > 2}

                if domain_tokens and title_tokens:
                    overlap = len(domain_tokens.intersection(title_tokens))
                    domain_title_match_score = round((overlap / len(domain_tokens)) * 100.0, 2)
                if url_tokens and title_tokens:
                    overlap_u = len(url_tokens.intersection(title_tokens))
                    url_title_match_score = round((overlap_u / len(url_tokens)) * 100.0, 2)

            # Favicon
            for link in soup.find_all("link", rel=True):
                rels = [r.lower() for r in link.get("rel", [])]
                if any("icon" in r for r in rels):
                    has_favicon = 1
                    break

            # Meta tags (robots, viewport, description)
            for meta in soup.find_all("meta"):
                name_attr = (meta.get("name") or meta.get("property") or "").lower()
                if name_attr == "robots":
                    robots = 1
                elif name_attr == "viewport":
                    is_responsive = 1
                elif name_attr in {"description", "og:description"} and (meta.get("content") or "").strip():
                    has_description = 1

            # Popups & Iframes
            no_of_popup = len(re.findall(r"window\.open\s*\(", html_text, re.IGNORECASE))
            no_of_iframe = len(soup.find_all("iframe"))

            # Forms & Input Fields
            for form in soup.find_all("form"):
                action = (form.get("action") or "").strip()
                if action.startswith("http://") or action.startswith("https://"):
                    action_host = (urllib.parse.urlparse(action).hostname or "").lower()
                    if action_host and action_host != hostname and (not ext.domain or ext.domain.lower() not in action_host):
                        has_external_form_submit = 1

            for inp in soup.find_all(["input", "button"]):
                inp_type = (inp.get("type") or "").lower()
                if inp_type in {"submit", "button"} or inp.name == "button":
                    has_submit_button = 1
                if inp_type == "hidden":
                    has_hidden_fields = 1
                if inp_type == "password":
                    has_password_field = 1

            # Social media & reference links
            social_domains = (
                "facebook.com",
                "twitter.com",
                "x.com",
                "linkedin.com",
                "instagram.com",
                "youtube.com",
                "github.com",
            )
            for a_tag in soup.find_all("a", href=True):
                href_val = a_tag["href"].strip()
                href_lower = href_val.lower()

                if any(sd in href_lower for sd in social_domains):
                    has_social_net = 1

                if not href_val or href_val in {"#", "javascript:void(0)", "javascript:;"}:
                    no_of_empty_ref += 1
                elif href_val.startswith("/") or href_val.startswith("#") or href_val.startswith("mailto:") or href_val.startswith("tel:"):
                    no_of_self_ref += 1
                elif href_val.startswith("http://") or href_val.startswith("https://"):
                    ref_host = (urllib.parse.urlparse(href_val).hostname or "").lower()
                    if ref_host == hostname or (ext.domain and ext.domain.lower() in ref_host):
                        no_of_self_ref += 1
                    else:
                        no_of_external_ref += 1
                else:
                    no_of_self_ref += 1

            # Resource counts
            no_of_image = len(soup.find_all("img"))
            no_of_css = len(
                [l for l in soup.find_all("link", rel=True) if "stylesheet" in [r.lower() for r in l.get("rel", [])]]
            ) + len(soup.find_all("style"))
            no_of_js = len(soup.find_all("script"))

            # Keyword & Copyright checks in visible text + URL
            visible_text = soup.get_text(separator=" ").lower() + " " + url_lower
            words_in_page = set(re.findall(r"[a-z0-9]+", visible_text))

            if words_in_page.intersection(BANK_KEYWORDS):
                bank_flag = 1
            if words_in_page.intersection(PAY_KEYWORDS):
                pay_flag = 1
            if words_in_page.intersection(CRYPTO_KEYWORDS):
                crypto_flag = 1

            if "©" in html_text or "&copy;" in html_text.lower() or "copyright" in visible_text or "all rights reserved" in visible_text:
                has_copyright_info = 1

        except requests.RequestException:
            reachable = False
            if url_tokens_all.intersection(BANK_KEYWORDS):
                bank_flag = 1
            if url_tokens_all.intersection(PAY_KEYWORDS):
                pay_flag = 1
            if url_tokens_all.intersection(CRYPTO_KEYWORDS):
                crypto_flag = 1
    else:
        if url_tokens_all.intersection(BANK_KEYWORDS):
            bank_flag = 1
        if url_tokens_all.intersection(PAY_KEYWORDS):
            pay_flag = 1
        if url_tokens_all.intersection(CRYPTO_KEYWORDS):
            crypto_flag = 1

    # Composite security score (HTTPS + HSTS + CSP)
    security_feature_sum = int(is_https + hsts_header_present + csp_header_present)

    # Assemble all 55 features in exact schema order matching feature_columns.json
    features_dict: Dict[str, Any] = {
        "URLLength": url_length,
        "DomainLength": domain_length,
        "IsDomainIP": is_domain_ip,
        "TLD": tld if tld else "unknown",
        "CharContinuationRate": char_continuation_rate,
        "TLDLegitimateProb": tld_legitimate_prob,
        "URLCharProb": url_char_prob,
        "TLDLength": tld_length,
        "NoOfSubDomain": no_of_subdomain,
        "HasObfuscation": has_obfuscation,
        "NoOfObfuscatedChar": no_of_obfuscated_char,
        "ObfuscationRatio": obfuscation_ratio,
        "NoOfLettersInURL": no_of_letters,
        "LetterRatioInURL": letter_ratio,
        "NoOfDegitsInURL": no_of_digits,
        "DegitRatioInURL": digit_ratio,
        "NoOfEqualsInURL": no_of_equals,
        "NoOfQMarkInURL": no_of_qmark,
        "NoOfAmpersandInURL": no_of_amp,
        "NoOfOtherSpecialCharsInURL": no_of_other_special,
        "SpacialCharRatioInURL": spacial_char_ratio,
        "LineOfCode": line_of_code,
        "LargestLineLength": largest_line_length,
        "HasTitle": has_title,
        "DomainTitleMatchScore": domain_title_match_score,
        "URLTitleMatchScore": url_title_match_score,
        "HasFavicon": has_favicon,
        "Robots": robots,
        "IsResponsive": is_responsive,
        "HasDescription": has_description,
        "NoOfPopup": no_of_popup,
        "NoOfiFrame": no_of_iframe,
        "HasSocialNet": has_social_net,
        "HasSubmitButton": has_submit_button,
        "Bank": bank_flag,
        "Pay": pay_flag,
        "Crypto": crypto_flag,
        "HasCopyrightInfo": has_copyright_info,
        "NoOfImage": no_of_image,
        "NoOfCSS": no_of_css,
        "NoOfJS": no_of_js,
        "NoOfSelfRef": no_of_self_ref,
        "NoOfEmptyRef": no_of_empty_ref,
        "NoOfExternalRef": no_of_external_ref,
        "IsHTTPS": is_https,
        "NoOfURLRedirect": no_of_url_redirect,
        "NoOfSelfRedirect": no_of_self_redirect,
        "HasExternalFormSubmit": has_external_form_submit,
        "HasHiddenFields": has_hidden_fields,
        "HasPasswordField": has_password_field,
        "HSTSHeaderPresent": hsts_header_present,
        "ContentSecurityPolicyPresent": csp_header_present,
        "SecurityFeatureSum": security_feature_sum,
        "PathLengthRatio": path_length_ratio,
        "HasSuspiciousKeywords": has_suspicious_keywords,
    }

    inspection_details = {
        "input_url": raw_url,
        "final_url": final_url,
        "domain": domain_full,
        "tld": tld if tld else "invalid",
        "valid_tld": is_valid_tld,
        "dns_resolved": dns_resolved,
        "reachable": reachable,
        "http_status": http_status,
        "page_title": (
            page_title
            if page_title
            else ("Domain Does Not Exist (Invalid TLD / DNS Failed)" if not dns_resolved else "No Title Detected")
        ),
        "security_headers": raw_headers,
    }

    return features_dict, inspection_details

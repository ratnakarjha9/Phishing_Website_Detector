import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import ipaddress
import socket
import re
import whois
from datetime import date


# 1. UsingIP
def using_ip(url):
    try:
        hostname = urlparse(url).hostname
        ipaddress.ip_address(hostname)
        return -1
    except:
        return 1


# 2. LongURL
def long_url(url):
    length = len(url)

    if length < 54:
        return 1
    elif length <= 75:
        return 0
    else:
        return -1


# 3. ShortURL
def short_url(url):
    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "goo.gl",
        "t.co",
        "ow.ly",
        "is.gd",
        "buff.ly"
    ]

    for shortener in shorteners:
        if shortener in url.lower():
            return -1

    return 1


# 4. Symbol@
def symbol_at(url):
    if "@" in url:
        return -1
    return 1


# 5. Redirecting//
def redirecting(url):
    if "//" in url[8:]:
        return -1
    return 1


# 6. PrefixSuffix-
def prefix_suffix(url):
    hostname = urlparse(url).hostname

    if hostname and "-" in hostname:
        return -1

    return 1


# 7. SubDomains
def sub_domains(url):
    hostname = urlparse(url).hostname

    if hostname is None:
        return -1

    parts = hostname.split(".")

    if len(parts) <= 2:
        return 1
    elif len(parts) == 3:
        return 0
    else:
        return -1


# 8. HTTPS
def https_check(url):
    if url.lower().startswith("https://"):
        return 1
    else:
        return -1


# 11. NonStdPort
def non_standard_port(url):
    try:
        parsed = urlparse(url)

        if parsed.port is None:
            return 1

        if parsed.port in [80, 443]:
            return 1

        return -1

    except:
        return -1


# 12. HTTPSDomainURL
def https_domain_url(url):
    hostname = urlparse(url).hostname

    if hostname and "https" in hostname.lower():
        return -1

    return 1


# 18. AbnormalURL
def abnormal_url(url):
    hostname = urlparse(url).hostname

    if hostname is None:
        return -1

    if hostname not in url:
        return -1

    return 1

def favicon(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        icon = soup.find("link", rel=lambda x: x and "icon" in x.lower())

        if icon:
            return 1
        else:
            return -1

    except:
        return -1
    

def request_url(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        hostname = urlparse(url).hostname

        tags = soup.find_all(["img", "script", "link"])

        external = 0
        total = len(tags)

        for tag in tags:
            source = tag.get("src") or tag.get("href")

            if source:
                full_url = urljoin(url, source)
                source_host = urlparse(full_url).hostname

                if source_host and source_host != hostname:
                    external += 1

        if total == 0:
            return 1

        ratio = external / total

        if ratio < 0.22:
            return 1
        elif ratio <= 0.61:
            return 0
        else:
            return -1

    except:
        return -1

def anchor_url(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        hostname = urlparse(url).hostname

        anchors = soup.find_all("a")

        if len(anchors) == 0:
            return 1

        suspicious = 0

        for a in anchors:
            href = a.get("href")

            if href:
                full_url = urljoin(url, href)
                anchor_host = urlparse(full_url).hostname

                if anchor_host and anchor_host != hostname:
                    suspicious += 1

        ratio = suspicious / len(anchors)

        if ratio < 0.31:
            return 1
        elif ratio <= 0.67:
            return 0
        else:
            return -1

    except:
        return -1


def links_in_script_tags(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        hostname = urlparse(url).hostname

        scripts = soup.find_all("script")

        if len(scripts) == 0:
            return 1

        external = 0

        for script in scripts:
            src = script.get("src")

            if src:
                full_url = urljoin(url, src)
                script_host = urlparse(full_url).hostname

                if script_host and script_host != hostname:
                    external += 1

        ratio = external / len(scripts)

        if ratio < 0.17:
            return 1
        elif ratio <= 0.81:
            return 0
        else:
            return -1

    except:
        return -1


def server_form_handler(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        forms = soup.find_all("form")

        if len(forms) == 0:
            return 1

        for form in forms:
            action = form.get("action")

            if action:
                full_url = urljoin(url, action)
                action_host = urlparse(full_url).hostname
                hostname = urlparse(url).hostname

                if action_host and action_host != hostname:
                    return -1

        return 1

    except:
        return -1

def info_email(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        text = soup.get_text().lower()

        if "mailto:" in response.text.lower() or "email" in text:
            return 1
        else:
            return -1

    except:
        return -1


def website_forwarding(url):
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)

        redirects = len(response.history)

        if redirects == 0:
            return 1
        elif redirects <= 2:
            return 0
        else:
            return -1

    except:
        return -1


def status_bar_cust(url):
    try:
        response = requests.get(url, timeout=5)

        html = response.text.lower()

        if "window.status" in html or "status=" in html:
            return -1
        else:
            return 1

    except:
        return -1


def disable_right_click(url):
    try:
        response = requests.get(url, timeout=5)

        html = response.text.lower()

        if "contextmenu" in html or "preventdefault" in html:
            return -1
        else:
            return 1

    except:
        return -1

def using_popup_window(url):
    try:
        response = requests.get(url, timeout=5)

        html = response.text.lower()

        if "window.open(" in html or "alert(" in html:
            return -1
        else:
            return 1

    except:
        return -1


def iframe_redirection(url):
    try:
        response = requests.get(url, timeout=5)
        html = response.text.lower()

        if "<iframe" in html or "frameborder" in html:
            return 1
        else:
            return -1

    except:
        return -1


def domain_reg_len(url):
    try:
        hostname = urlparse(url).hostname

        if hostname is None:
            return -1

        domain_info = whois.whois(hostname)

        creation_date = domain_info.creation_date
        expiration_date = domain_info.expiration_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        if creation_date is None or expiration_date is None:
            return -1

        age_months = (
            (expiration_date.year - creation_date.year) * 12
            + (expiration_date.month - creation_date.month)
        )

        if age_months >= 12:
            return 1
        else:
            return -1

    except:
        return -1

def age_of_domain(url):
    try:
        hostname = urlparse(url).hostname

        if hostname is None:
            return -1

        domain_info = whois.whois(hostname)

        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            return -1

        today = date.today()

        age_months = (
            (today.year - creation_date.year) * 12
            + (today.month - creation_date.month)
        )

        if age_months >= 6:
            return 1
        else:
            return -1

    except:
        return -1

def dns_recording(url):
    try:
        hostname = urlparse(url).hostname

        if hostname is None:
            return -1

        socket.gethostbyname(hostname)

        return 1

    except:
        return -1

def website_traffic(url):
    try:
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            return 1
        else:
            return 0

    except:
        return -1

def page_rank(url):
    try:
        hostname = urlparse(url).hostname

        if hostname is None:
            return -1

        response = requests.get(
            "https://" + hostname,
            timeout=5
        )

        if response.status_code == 200:
            return 1
        else:
            return -1

    except:
        return -1

def google_index(url):
    try:
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            return 1
        else:
            return -1

    except:
        return -1

def links_pointing_to_page(url):
    try:
        response = requests.get(url, timeout=5)

        soup = BeautifulSoup(response.text, "html.parser")

        links = soup.find_all("a", href=True)

        number_of_links = len(links)

        if number_of_links == 0:
            return 1
        elif number_of_links <= 2:
            return 0
        else:
            return -1

    except:
        return -1

def stats_report(url):
    try:
        hostname = urlparse(url).hostname

        if hostname is None:
            return -1

        suspicious_domains = [
            "at.ua",
            "usa.cc",
            "pe.hu",
            "esy.es",
            "hol.es",
            "sweddy.com",
            "myjino.ru",
            "96.lt",
            "ow.ly"
        ]

        for domain in suspicious_domains:
            if domain in hostname.lower():
                return -1

        socket.gethostbyname(hostname)

        return 1

    except:
        return 1

def extract_features(url):

    features = []

    features.append(using_ip(url))
    features.append(long_url(url))
    features.append(short_url(url))
    features.append(symbol_at(url))
    features.append(redirecting(url))
    features.append(prefix_suffix(url))
    features.append(sub_domains(url))
    features.append(https_check(url))

    features.append(domain_reg_len(url))

    features.append(favicon(url))

    features.append(non_standard_port(url))
    features.append(https_domain_url(url))
    features.append(request_url(url))
    features.append(anchor_url(url))
    features.append(links_in_script_tags(url))
    features.append(server_form_handler(url))
    features.append(info_email(url))
    features.append(abnormal_url(url))
    features.append(website_forwarding(url))
    features.append(status_bar_cust(url))
    features.append(disable_right_click(url))
    features.append(using_popup_window(url))
    features.append(iframe_redirection(url))

    features.append(age_of_domain(url))
    features.append(dns_recording(url))
    features.append(website_traffic(url))
    features.append(page_rank(url))
    features.append(google_index(url))
    features.append(links_pointing_to_page(url))
    features.append(stats_report(url))

    return features


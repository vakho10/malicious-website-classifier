import re
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse, urljoin

import pandas as pd

# Optional dependencies - import individually to isolate failures
HAS_REQUESTS = False
HAS_WHOIS = False
HAS_BS4 = False

try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    pass

try:
    import whois

    HAS_WHOIS = True
except (ImportError, TypeError):
    # TypeError can occur with whois on older Python versions
    pass

try:
    from bs4 import BeautifulSoup

    HAS_BS4 = True
except ImportError:
    pass


class FeatureExtractor:
    """Extracts UCI phishing features from URLs"""

    FEATURE_COLUMNS = [
        'SFH', 'popUpWindow', 'SSLfinal_State', 'Request_URL',
        'URL_of_Anchor', 'web_traffic', 'URL_Length', 'age_of_domain', 'having_IP_Address'
    ]

    @staticmethod
    def extract(url):
        """Convert URL to 9-feature vector matching UCI dataset"""
        parsed = urlparse(url if '://' in url else 'http://' + url)
        host = parsed.netloc

        # Fetch HTML
        soup = None
        if HAS_REQUESTS and HAS_BS4:
            try:
                r = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
                soup = BeautifulSoup(r.text, "html.parser")
            except:
                pass

        features = {
            'SFH': FeatureExtractor._sfh(soup, host),
            'popUpWindow': FeatureExtractor._popup(soup),
            'SSLfinal_State': FeatureExtractor._ssl(url, parsed, host),
            'Request_URL': FeatureExtractor._request_url(soup, host),
            'URL_of_Anchor': FeatureExtractor._anchor_url(soup, host),
            'web_traffic': FeatureExtractor._web_traffic(host),
            'URL_Length': FeatureExtractor._url_length(url),
            'age_of_domain': FeatureExtractor._domain_age(host),
            'having_IP_Address': FeatureExtractor._has_ip(host)
        }

        return pd.DataFrame([features], columns=FeatureExtractor.FEATURE_COLUMNS)

    @staticmethod
    def _has_ip(host):
        return -1 if re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}', host.split(':')[0]) else 1

    @staticmethod
    def _url_length(url):
        L = len(url)
        return 1 if L < 54 else (0 if L <= 75 else -1)

    @staticmethod
    def _ssl(url, parsed, host):
        if parsed.scheme != 'https':
            return -1
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(3)
                s.connect((host, 443))
                return 1 if s.getpeercert() else 0
        except:
            return 0

    @staticmethod
    def _popup(soup):
        if not soup:
            return 0
        text = soup.get_text()
        return -1 if re.search(r'window\.open|alert\s*\(|showModalDialog', text, re.I) else 1

    @staticmethod
    def _sfh(soup, host):
        if not soup:
            return 0
        forms = soup.find_all('form')
        if not forms:
            return 1

        for form in forms:
            action = form.get('action', '').strip()
            if not action or action.startswith('javascript'):
                return -1
            abs_action = urljoin(f"http://{host}", action)
            if urlparse(abs_action).netloc.split(':')[0] != host.split(':')[0]:
                return 0
        return 1

    @staticmethod
    def _request_url(soup, host):
        if not soup:
            return 0

        urls = [tag.get('src') or tag.get('href')
                for tag in soup.find_all(['img', 'script', 'link', 'iframe'])]
        urls = [u for u in urls if u]

        if not urls:
            return 1

        same = sum(1 for u in urls if urlparse(urljoin(f"http://{host}", u)).netloc.split(':')[0] == host.split(':')[0])
        ratio = same / len(urls)
        return 1 if ratio > 0.5 else (-1 if ratio == 0 else 0)

    @staticmethod
    def _anchor_url(soup, host):
        if not soup:
            return 0

        anchors = [a.get('href') for a in soup.find_all('a') if a.get('href')]
        if not anchors:
            return 1

        suspicious = sum(1 for a in anchors if not a.strip() or a.startswith(('javascript', '#')) or
                         urlparse(urljoin(f"http://{host}", a)).netloc.split(':')[0] != host.split(':')[0])
        ratio = suspicious / len(anchors)
        return -1 if ratio > 0.5 else (1 if ratio == 0 else 0)

    @staticmethod
    def _web_traffic(domain):
        if not HAS_REQUESTS:
            return 0
        try:
            r = requests.head(f"http://{domain}", timeout=3)
            return 1 if r.status_code < 400 else 0
        except:
            return 0

    @staticmethod
    def _domain_age(domain):
        if not HAS_WHOIS:
            return 0
        try:
            w = whois.whois(domain)
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if creation:
                age = (datetime.utcnow() - creation).days / 365.25
                return 1 if age >= 1 else (0 if age > 0 else -1)
        except:
            pass
        return 0

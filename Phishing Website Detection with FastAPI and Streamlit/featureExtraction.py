# coding: utf-8

import pandas as pd
from urllib.parse import urlparse
import re
from bs4 import BeautifulSoup
import whois
import urllib.request
import time
import socket
from urllib.error import HTTPError
from datetime import datetime


class FeatureExtraction:
    def getProtocol(self, url):
        return urlparse(url).scheme

    def getDomain(self, url):
        return urlparse(url).netloc

    def getPath(self, url):
        return urlparse(url).path

    def havingIP(self, url):
        pattern = r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])'
        return 1 if re.search(pattern, url) else 0

    def long_url(self, url):
        length = len(url)
        return 0 if length < 54 else 2 if length <= 75 else 1

    def have_at_symbol(self, url):
        return 1 if "@" in url else 0

    def redirection(self, url):
        return 1 if "//" in urlparse(url).path else 0

    def prefix_suffix_separation(self, url):
        return 1 if "-" in urlparse(url).netloc else 0

    def sub_domains(self, url):
        dots = url.count(".")
        return 0 if dots < 3 else 2 if dots == 3 else 1

    def shortening_service(self, url):
        pattern = r'(bit\.ly|goo\.gl|tinyurl\.com|ow\.ly|t\.co|bitly\.com|is\.gd|buff\.ly|adf\.ly)'
        return 1 if re.search(pattern, url) else 0

    def web_traffic(self, url):
        try:
            response = urllib.request.urlopen(f"http://data.alexa.com/data?cli=10&dat=s&url={url}")
            rank = BeautifulSoup(response.read(), "xml").find("REACH")["RANK"]
            return 0 if int(rank) < 100000 else 2
        except (TypeError, HTTPError):
            return 1

    def domain_registration_length(self, url):
        try:
            domain_name = whois.whois(urlparse(url).netloc)
            expiration_date = domain_name.expiration_date
            today = datetime.now()
            if not expiration_date:
                return 1
            if isinstance(expiration_date, list):
                return 2
            registration_length = abs((expiration_date - today).days)
            return 1 if registration_length / 365 <= 1 else 0
        except:
            return 1

    def age_domain(self, url):
        try:
            domain_name = whois.whois(urlparse(url).netloc)
            creation_date = domain_name.creation_date
            expiration_date = domain_name.expiration_date
            if not creation_date or not expiration_date:
                return 1
            if isinstance(creation_date, list) or isinstance(expiration_date, list):
                return 2
            ageofdomain = abs((expiration_date - creation_date).days)
            return 1 if (ageofdomain / 30) < 6 else 0
        except:
            return 1

    def dns_record(self, url):
        try:
            whois.whois(urlparse(url).netloc)
            return 0
        except:
            return 1

    def statistical_report(self, url):
        hostname = urlparse(url).netloc
        suspicious_keywords = r'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly'
        known_ips = r'146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88'
        try:
            ip_address = socket.gethostbyname(hostname)
            if re.search(suspicious_keywords, url) or re.search(known_ips, ip_address):
                return 1
            return 0
        except:
            return 1

    def https_token(self, url):
        try:
            match = re.search(r'https?://', url)
            if match:
                rest = url[match.end():]
                return 1 if re.search(r'https?', rest) else 0
            return 0
        except:
            return 1


def getAttributess(url):
    fe = FeatureExtraction()
    features = {
        'Domain': fe.getDomain(url),
        'Path': fe.getPath(url),
        'URL_Length': fe.long_url(url),
        'Redirection_//_symbol': fe.redirection(url),
        'Prefix_suffix_separation': fe.prefix_suffix_separation(url),
        'Sub_domains': fe.sub_domains(url),
        'Tiny_URL': fe.shortening_service(url),
        'Web_Traffic': fe.web_traffic(url),
        'Domain_Registration_Length': fe.domain_registration_length(url),
        'DNS_Record': fe.dns_record(url),
        'Statistical_Report': fe.statistical_report(url),
        'Age_Domain': fe.age_domain(url),
        'HTTPS_Token': fe.https_token(url),
    }
    return pd.DataFrame([features])

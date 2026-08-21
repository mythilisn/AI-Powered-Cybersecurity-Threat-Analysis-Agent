import re
from typing import Dict, List, Set

class IOCExtractor:
    DEFANG_PATTERNS = [
        (r'\[\.\]', '.'),
        (r'\(\.\)', '.'),
        (r'\{\.\}', '.'),
        (r'hxxp', 'http'),
        (r'\[:\]', ':'),
        (r'\[/\]', '/'),
    ]

    IPV4_PATTERN = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    IPV6_PATTERN = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    MD5_PATTERN = r'\b[a-fA-F0-9]{32}\b'
    SHA1_PATTERN = r'\b[a-fA-F0-9]{40}\b'
    SHA256_PATTERN = r'\b[a-fA-F0-9]{64}\b'
    CVE_PATTERN = r'\bCVE-\d{4}-\d{4,7}\b'
    EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
    URL_PATTERN = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*'
    DOMAIN_PATTERN = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'

    @classmethod
    def clean_text(cls, raw_text: str) -> str:
        text = raw_text
        for pattern, replacement in cls.DEFANG_PATTERNS:
            text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
        return text

    @classmethod
    def extract_all(cls, raw_text: str) -> Dict[str, List[str]]:
        cleaned_text = cls.clean_text(raw_text)

        ipv4s: Set[str] = set(re.findall(cls.IPV4_PATTERN, cleaned_text))
        ipv6s: Set[str] = set(re.findall(cls.IPV6_PATTERN, cleaned_text))
        md5s: Set[str] = set(re.findall(cls.MD5_PATTERN, cleaned_text))
        sha1s: Set[str] = set(re.findall(cls.SHA1_PATTERN, cleaned_text))
        sha256s: Set[str] = set(re.findall(cls.SHA256_PATTERN, cleaned_text))
        cves: Set[str] = set(re.findall(cls.CVE_PATTERN, cleaned_text, flags=re.IGNORECASE))
        emails: Set[str] = set(re.findall(cls.EMAIL_PATTERN, cleaned_text, flags=re.IGNORECASE))
        urls: Set[str] = set(re.findall(cls.URL_PATTERN, cleaned_text, flags=re.IGNORECASE))

        all_domains = set(re.findall(cls.DOMAIN_PATTERN, cleaned_text, flags=re.IGNORECASE))
        clean_domains = {
            d for d in all_domains
            if d not in ipv4s and not any(d in url for url in urls) and not any(d in email for email in emails)
        }

        return {
            "ipv4": sorted(list(ipv4s)),
            "ipv6": sorted(list(ipv6s)),
            "domains": sorted(list(clean_domains)),
            "urls": sorted(list(urls)),
            "md5": sorted(list(md5s)),
            "sha1": sorted(list(sha1s)),
            "sha256": sorted(list(sha256s)),
            "cve": sorted(list(cves)),
            "emails": sorted(list(emails)),
            "total_count": len(ipv4s) + len(ipv6s) + len(clean_domains) + len(urls) + len(md5s) + len(sha1s) + len(sha256s) + len(cves) + len(emails)
        }
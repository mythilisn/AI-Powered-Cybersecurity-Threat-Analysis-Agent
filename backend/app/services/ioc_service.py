import re
from typing import Dict, List, Any

class IoCExtractorService:
    # Deterministic Regex patterns for CTI
    IPV4_REGEX = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    IPV6_REGEX = r'(?i)\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b'
    URL_REGEX = r'(?i)\b(?:https?|ftp|hxxps?):\/\/[^\s/$.?#].[^\s]*'
    DOMAIN_REGEX = r'(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|xyz|info|top|ru|cn|cc|biz|online|site|live|me|cloud|cc|tk)\b'
    EMAIL_REGEX = r'(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b'
    MD5_REGEX = r'\b[a-fA-F0-9]{32}\b'
    SHA1_REGEX = r'\b[a-fA-F0-9]{40}\b'
    SHA256_REGEX = r'\b[a-fA-F0-9]{64}\b'
    CVE_REGEX = r'(?i)\bCVE-\d{4}-\d{4,7}\b'

    @staticmethod
    def defang(value: str) -> str:
        """Neutralizes executable or clickable threat indicators."""
        return (
            value.replace("http://", "hxxp://")
                 .replace("https://", "hxxps://")
                 .replace(".", "[.]")
                 .replace("@", "[at]")
        )

    def extract_iocs(self, text: str) -> Dict[str, Any]:
        if not text:
            return {"indicators": {}, "stats": {}, "threat_verdict": "BENIGN", "threat_score": 0}

        # 1. Regex Extraction
        raw_urls = re.findall(self.URL_REGEX, text)
        raw_ips = re.findall(self.IPV4_REGEX, text) + re.findall(self.IPV6_REGEX, text)
        raw_emails = re.findall(self.EMAIL_REGEX, text)
        raw_sha256 = re.findall(self.SHA256_REGEX, text)
        raw_sha1 = re.findall(self.SHA1_REGEX, text)
        raw_md5 = re.findall(self.MD5_REGEX, text)
        raw_cves = [c.upper() for c in re.findall(self.CVE_REGEX, text)]
        
        # Domain parsing (exclude domains already captured in URLs/Emails)
        potential_domains = set(re.findall(self.DOMAIN_REGEX, text))
        clean_domains = [d for d in potential_domains if not any(d in url for url in raw_urls) and not any(d in email for email in raw_emails)]

        # 2. Structure & De-fang Indicators
        indicators = {
            "urls": [{"raw": u, "defanged": self.defang(u), "type": "URL"} for u in set(raw_urls)],
            "ips": [{"raw": ip, "defanged": self.defang(ip), "type": "IPv4/IPv6"} for ip in set(raw_ips)],
            "domains": [{"raw": d, "defanged": self.defang(d), "type": "Domain"} for d in set(clean_domains)],
            "emails": [{"raw": e, "defanged": self.defang(e), "type": "Email"} for e in set(raw_emails)],
            "sha256": [{"raw": h.lower(), "defanged": h.lower(), "type": "SHA-256"} for h in set(raw_sha256)],
            "sha1": [{"raw": h.lower(), "defanged": h.lower(), "type": "SHA-1"} for h in set(raw_sha1)],
            "md5": [{"raw": h.lower(), "defanged": h.lower(), "type": "MD5"} for h in set(raw_md5)],
            "cves": [{"raw": c, "defanged": c, "type": "CVE"} for c in set(raw_cves)],
        }

        # 3. Calculate Threat Score & Verdict
        total_iocs = sum(len(v) for v in indicators.values())
        threat_score = min(100, (len(indicators["sha256"]) * 30) + (len(indicators["urls"]) * 25) + (len(indicators["ips"]) * 15) + (len(indicators["cves"]) * 20))
        
        if threat_score >= 70:
            threat_verdict = "CRITICAL"
        elif threat_score >= 40:
            threat_verdict = "SUSPICIOUS"
        elif threat_score > 0:
            threat_verdict = "LOW"
        else:
            threat_verdict = "CLEAN"

        return {
            "total_count": total_iocs,
            "threat_score": threat_score,
            "threat_verdict": threat_verdict,
            "indicators": indicators
        }
import io
import email
from typing import Tuple
from pypdf import PdfReader
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, DNS, DNSQR

class FileParserService:

    @staticmethod
    def extract_text_from_file(filename: str, content: bytes) -> str:
        """
        Parses different file formats into a single raw text string
        ready for regex IoC extraction.
        """
        lower_name = filename.lower()

        # 1. Plain Text / Raw Logs
        if lower_name.endswith(('.txt', '.log', '.csv', '.json')):
            return content.decode('utf-8', errors='ignore')

        # 2. Phishing Email Files (.eml, .msg)
        elif lower_name.endswith('.eml'):
            msg = email.message_from_bytes(content)
            extracted_parts = []

            # Headers
            for header in ['From', 'To', 'Subject', 'Received', 'Reply-To', 'Return-Path']:
                if msg[header]:
                    extracted_parts.append(f"{header}: {msg[header]}")

            # Body payload
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    if content_type in ["text/plain", "text/html"]:
                        payload = part.get_payload(decode=True)
                        if payload:
                            extracted_parts.append(payload.decode('utf-8', errors='ignore'))
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    extracted_parts.append(payload.decode('utf-8', errors='ignore'))

            return "\n".join(extracted_parts)

        # 3. Threat Reports / Intelligence PDFs
        elif lower_name.endswith('.pdf'):
            pdf_file = io.BytesIO(content)
            reader = PdfReader(pdf_file)
            text_pages = []
            for page in reader.pages:
                extracted = page.extract_text()
                if extracted:
                    text_pages.append(extracted)
            return "\n".join(text_pages)

        # 4. Network Packet Captures (.pcap, .cap)
        elif lower_name.endswith(('.pcap', '.cap', '.pcapng')):
            pcap_file = io.BytesIO(content)
            packets = rdpcap(pcap_file)
            extracted_data = []

            for pkt in packets:
                # Capture IPs
                if IP in pkt:
                    extracted_data.append(f"IPv4 Src: {pkt[IP].src} Dst: {pkt[IP].dst}")
                if IPv6 in pkt:
                    extracted_data.append(f"IPv6 Src: {pkt[IPv6].src} Dst: {pkt[IPv6].dst}")
                # Capture DNS queries (domains)
                if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
                    dns_layer = pkt.getlayer(DNSQR)
                    if dns_layer and dns_layer.qname:
                        domain_str = dns_layer.qname.decode('utf-8', errors='ignore').rstrip('.')
                        extracted_data.append(f"DNS Query: {domain_str}")
                # Capture HTTP/Raw string segments
                if pkt.haslayer(TCP) or pkt.haslayer(UDP):
                    raw_payload = bytes(pkt.payload)
                    if raw_payload:
                        extracted_data.append(raw_payload.decode('utf-8', errors='ignore'))

            return "\n".join(extracted_data)

        else:
            # Fallback to UTF-8 decoded text
            return content.decode('utf-8', errors='ignore')

import re

def extract_header_info(header_text):
    headers_of_interest = ["cookie", "user-agent", "Set-Cookie", "referer", "set-cookie"]
    header_info = {}
    for header in headers_of_interest:
        pattern = re.compile(f"{header}\s*:\s*(.*)", re.IGNORECASE)
        match = pattern.search(header_text)
        if match:
            header_info[header] = match.group(1).strip()
    return header_info

def extract_payload_info(payload_text):
    payload_info = {}
    for line in payload_text.split("\n"):
        if ": " in line:
            key, value = line.split(": ", 1)
            payload_info[key] = value
    return payload_info

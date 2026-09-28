import hashlib
import math
import re
from typing import Union, Dict

def calculate_sha256(data: Union[str, bytes]) -> str:
    """Calculates the SHA-256 hash of a string or bytes input."""
    if isinstance(data, str):
        data_bytes = data.encode('utf-8', errors='ignore')
    else:
        data_bytes = data
    return hashlib.sha256(data_bytes).hexdigest()

def calculate_hashes(data: Union[str, bytes]) -> Dict[str, str]:
    """Returns SHA-256, SHA-1, and MD5 hashes."""
    if isinstance(data, str):
        data_bytes = data.encode('utf-8', errors='ignore')
    else:
        data_bytes = data
    return {
        "sha256": hashlib.sha256(data_bytes).hexdigest(),
        "sha1": hashlib.sha1(data_bytes).hexdigest(),
        "md5": hashlib.md5(data_bytes).hexdigest()
    }

def calculate_entropy(data: Union[str, bytes]) -> float:
    """
    Calculates the Shannon Entropy of a string or byte sequence.
    Entropy ranges from 0.0 (completely uniform/predictable) to 8.0 (completely random/encrypted).
    """
    if isinstance(data, str):
        data_bytes = data.encode('utf-8', errors='ignore')
    else:
        data_bytes = data

    if not data_bytes:
        return 0.0

    length = len(data_bytes)
    freq_map = {}
    for byte in data_bytes:
        freq_map[byte] = freq_map.get(byte, 0) + 1

    entropy = 0.0
    for count in freq_map.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)

def defang_string(text: str) -> str:
    """De-fangs IPs, URLs, and domains to prevent accidental clicks."""
    text = re.sub(r'http://', 'http[:]//', text, flags=re.IGNORECASE)
    text = re.sub(r'https://', 'https[:]//', text, flags=re.IGNORECASE)
    text = re.sub(r'(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})', r'\1.\2.\3[.]\4', text)
    text = text.replace('.com', '[.]com').replace('.net', '[.]net').replace('.org', '[.]org')
    # Clean up double defanging if present
    text = text.replace('[.][.]', '[.]')
    return text

def refang_string(text: str) -> str:
    """Normalizes de-fanged indicators back to clean strings for exact matching."""
    text = text.replace('[.]', '.')
    text = text.replace('[:]', ':')
    text = text.replace('hxxp', 'http')
    text = text.replace('HXXP', 'HTTP')
    return text

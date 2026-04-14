"""
IP Classification Utility
Classifies IP addresses as 'internal' or 'external' based on RFC 1918 and other reserved ranges
"""

import ipaddress
from typing import Literal, Optional


# IPv4 private/reserved networks
IPV4_PRIVATE_NETWORKS = [
    # RFC 1918 Private ranges
    ipaddress.ip_network('10.0.0.0/8'),        # Class A Private
    ipaddress.ip_network('172.16.0.0/12'),     # Class B Private
    ipaddress.ip_network('192.168.0.0/16'),    # Class C Private
    # Loopback
    ipaddress.ip_network('127.0.0.0/8'),       # Loopback
    # Link-local
    ipaddress.ip_network('169.254.0.0/16'),    # Link-local
    # CGNAT (Carrier-grade NAT)
    ipaddress.ip_network('100.64.0.0/10'),     # CGNAT
]

# IPv6 private/reserved networks
IPV6_PRIVATE_NETWORKS = [
    ipaddress.ip_network('::1/128'),           # Loopback
    ipaddress.ip_network('fc00::/7'),          # Unique local addresses
    ipaddress.ip_network('fe80::/10'),         # Link-local
]


def is_private_ip(ip: str) -> bool:
    """
    Check if an IP address is a private/internal address.

    Args:
        ip: IP address string (IPv4 or IPv6)

    Returns:
        True if the IP is private/internal, False otherwise
    """
    if not ip or not isinstance(ip, str):
        return False

    try:
        ip_obj = ipaddress.ip_address(ip.strip())

        if isinstance(ip_obj, ipaddress.IPv4Address):
            for network in IPV4_PRIVATE_NETWORKS:
                if ip_obj in network:
                    return True
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            for network in IPV6_PRIVATE_NETWORKS:
                if ip_obj in network:
                    return True

        return False
    except ValueError:
        # Invalid IP address format
        return False


def classify_ip(ip: str) -> Literal['internal', 'external']:
    """
    Classify an IP address as 'internal' or 'external'.

    Args:
        ip: IP address string (IPv4 or IPv6)

    Returns:
        'internal' for private/reserved addresses, 'external' for public addresses
    """
    return 'internal' if is_private_ip(ip) else 'external'


def get_ip_classification_details(ip: str) -> dict:
    """
    Get detailed classification information for an IP address.

    Args:
        ip: IP address string (IPv4 or IPv6)

    Returns:
        Dictionary with classification details
    """
    result = {
        'ip': ip,
        'classification': 'external',
        'is_private': False,
        'ip_version': None,
        'matched_range': None,
    }

    if not ip or not isinstance(ip, str):
        return result

    try:
        ip_obj = ipaddress.ip_address(ip.strip())
        result['is_private'] = is_private_ip(ip)
        result['classification'] = 'internal' if result['is_private'] else 'external'

        if isinstance(ip_obj, ipaddress.IPv4Address):
            result['ip_version'] = 4
            if result['is_private']:
                for network in IPV4_PRIVATE_NETWORKS:
                    if ip_obj in network:
                        result['matched_range'] = str(network)
                        break
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            result['ip_version'] = 6
            if result['is_private']:
                for network in IPV6_PRIVATE_NETWORKS:
                    if ip_obj in network:
                        result['matched_range'] = str(network)
                        break

        return result
    except ValueError:
        return result


def filter_external_ips(ips: list) -> list:
    """
    Filter a list of IPs to only include external (public) addresses.

    Args:
        ips: List of IP address strings

    Returns:
        List of external IP addresses only
    """
    return [ip for ip in ips if classify_ip(ip) == 'external']


def filter_internal_ips(ips: list) -> list:
    """
    Filter a list of IPs to only include internal (private) addresses.

    Args:
        ips: List of IP address strings

    Returns:
        List of internal IP addresses only
    """
    return [ip for ip in ips if classify_ip(ip) == 'internal']


def is_valid_ip(ip: str) -> bool:
    """
    Check if a string is a valid IP address.

    Args:
        ip: IP address string

    Returns:
        True if valid IP address, False otherwise
    """
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False

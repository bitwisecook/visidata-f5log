import re
from ipaddress import ip_network, ip_address

# I used rxgx to generate this regex
_find_ip_addresses = re.compile(
    r"(?P<ip>(?P<ipv4>(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})|(?P<ipv6>(?:(?::(?::[0-9A-Fa-f]{1,4}){1,7}|::|[0-9A-Fa-f]{1,4}(?::(?::[0-9A-Fa-f]{1,4}){1,6}|::|:[0-9A-Fa-f]{1,4}(?::(?::[0-9A-Fa-f]{1,4}){1,5}|::|:[0-9A-Fa-f]{1,4}(?::(?::[0-9A-Fa-f]{1,4}){1,4}|::|:[0-9A-Fa-f]{1,4}(?::(?::[0-9A-Fa-f]{1,4}){1,3}|::|:[0-9A-Fa-f]{1,4}(?::(?::[0-9A-Fa-f]{1,4}){1,2}|::|:[0-9A-Fa-f]{1,4}(?:::[0-9A-Fa-f]{1,4}|::|:[0-9A-Fa-f]{1,4}(?:::|:[0-9A-Fa-f]{1,4}))))))))|(?::(?::[0-9A-Fa-f]{1,4}){0,5}|[0-9A-Fa-f]{1,4}(?::(?::[0-9A-Fa-f]{1,4}){0,4}|:[0-9A-Fa-f]{1,4}(?::(?::[0-9A-Fa-f]{1,4}){0,3}|:[0-9A-Fa-f]{1,4}(?::(?::[0-9A-Fa-f]{1,4}){0,2}|:[0-9A-Fa-f]{1,4}(?::(?::[0-9A-Fa-f]{1,4})?|:[0-9A-Fa-f]{1,4}(?::|:[0-9A-Fa-f]{1,4})))))):(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})))"
)


def replace_domain(msg):
    domains = [
        ("internal.com", "fake.com"),
        ("other.com", "fake2.com"),
    ]
    ret = msg
    for domain in domains:
        ret = ret.replace(domain[0], domain[1])
    return ret


def replace_network(msg):
    nets = [
        (ip_network("123.45.0.0/24"), ip_network("234.56.0.0/24")),
        (ip_network("45.67.0.0/16"), ip_network("56.78.0.0/16")),
    ]
    ret = ""
    prev_end = 0
    for ip_str in _find_ip_addresses.finditer(msg):
        try:
            ip = ip_address(ip_str.groupdict()["ip"])
        except ValueError:
            continue
        for net in nets:
            if ip in net[0]:
                new_ip = ip_address(
                    int(ip) - int(net[0].network_address) + int(net[1].network_address)
                )
                ret += msg[prev_end : ip_str.start()]
                ret += str(new_ip)
                prev_end = ip_str.end()
    ret += msg[prev_end:]
    return ret


# here we
replacers = [replace_domain, replace_network]

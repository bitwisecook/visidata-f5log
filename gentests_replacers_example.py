from ipaddress import ip_network, ip_address
import random
import re
import string

with open("/usr/share/dict/words", "r") as words_file:
    _words = [_.lower() for _ in words_file.read().splitlines() if len(_) < 8]

# I used rxgx to generate this regex
_find_ip_addresses = re.compile(
    r"(?P<ip>(?P<ipv4>(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})|(?P<ipv6>(?:(?::(?::[0-9A-Fa-f]{1,4}){1,7}|::|[0-9A-Fa-f]{1,4}(?::(?::[0-9A-Fa-f]{1,4}){1,6}|::|:[0-9A-Fa-f]{1,4}(?::(?::[0-9A-Fa-f]{1,4}){1,5}|::|:[0-9A-Fa-f]{1,4}(?::(?::[0-9A-Fa-f]{1,4}){1,4}|::|:[0-9A-Fa-f]{1,4}(?::(?::[0-9A-Fa-f]{1,4}){1,3}|::|:[0-9A-Fa-f]{1,4}(?::(?::[0-9A-Fa-f]{1,4}){1,2}|::|:[0-9A-Fa-f]{1,4}(?:::[0-9A-Fa-f]{1,4}|::|:[0-9A-Fa-f]{1,4}(?:::|:[0-9A-Fa-f]{1,4}))))))))|(?::(?::[0-9A-Fa-f]{1,4}){0,5}|[0-9A-Fa-f]{1,4}(?::(?::[0-9A-Fa-f]{1,4}){0,4}|:[0-9A-Fa-f]{1,4}(?::(?::[0-9A-Fa-f]{1,4}){0,3}|:[0-9A-Fa-f]{1,4}(?::(?::[0-9A-Fa-f]{1,4}){0,2}|:[0-9A-Fa-f]{1,4}(?::(?::[0-9A-Fa-f]{1,4})?|:[0-9A-Fa-f]{1,4}(?::|:[0-9A-Fa-f]{1,4})))))):(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})))"
)
_find_hostnames = re.compile(
    r"(?P<hostname>bigip[1234]\d)",
)
_find_certcn = re.compile(
    r"Certificate\s'(?P<cn>[^']+)'\sin\sfile\s/.*/(?P<certfn>(?P<profname>\S+)\.crt)\s"
)

_nets = [
    (ip_network("10.0.0.0/8"), ip_network("10.0.0.0/8")),
    (ip_network("172.16.0.0/12"), ip_network("172.16.0.0/12")),
    (ip_network("192.168.0.0/16"), ip_network("192.168.0.0/16")),
]

for n in range(0, 230):
    _nets.append(
        (ip_network(f"{n}.0.0.0/8"), ip_network(f"{random.randrange(1,230)}.0.0.0/8"))
    )

for n in range(0, 0xFF):
    _nets.append(
        (
            ip_network(f"{n:x}00::/8"),
            ip_network(
                f"{random.randrange(0,255):x}{random.randrange(0,255):x}:{random.randrange(0,255):x}{random.randrange(0,255):x}::/32"
            ),
        )
    )


_domains = [
    ("gslb.company.com", "gtm.company.com"),
    ("company.com", "company.com"),
    ("company.internal", "internal.com"),
]


_rand_fqdn = {
    None: "",
}
_rand_hostname = {
    None: "",
}
_rand_ip = {
    None: "",
}
_rand_cn = {
    None: "",
}
_rand_cert_fn = {
    None: "",
}
_tld = [
    ".com",
    ".org",
    ".net",
    ".co.uk",
    ".com.sg",
    ".com.au",
    ".com.nz",
    ".is",
    ".id.au",
]


def randstr(l):
    return random.choice(string.ascii_lowercase) + "".join(
        random.choice([*string.ascii_lowercase, *string.digits]) for _ in range(l)
    )


def randfqdn(fqdn, l=3):
    global _rand_fqdn, _tld
    if fqdn not in _rand_fqdn:
        _rand_fqdn[fqdn] = (
            random.choice(_words)
            + ".".join([random.choice(_words) for _ in range(l - 1)])
            + random.choice(_tld)
        )
    return _rand_fqdn[fqdn]


def randhostname(hostname):
    global _rand_hostname, _tld
    if hostname not in _rand_hostname:
        _rand_hostname[hostname] = f"lb{random.randrange(1,99)}"
    return _rand_hostname[hostname]


def randcn(cn):
    global _rand_cn, _tld
    if cn not in _rand_cn:
        _rand_cn[
            cn
        ] = f"CN={randfqdn(cn)},OU={random.choice(_words)},O={random.choice(_words)},L={random.choice(_words)},ST={random.choice(_words)},C={random.choice(_words)}"
    return _rand_cn[cn]


def randcertfn(cn, profname):
    global _rand_cn, _tld
    if cn not in _rand_cn:
        _rand_cn[cn] = f"cert-{randfqdn(profname)}.crt"
    return _rand_cn[cn]


def randip(ip, net):
    global _rand_ip
    if ip not in _rand_ip:
        _rand_ip[ip] = ip_address(
            int(ip)
            - int(net[0].network_address)
            + int(net[1].network_address)
            + random.randrange(0, 1024 * 1024)
        )
    return _rand_ip[ip]


def replace_hostnames(msg):
    ret = ""
    prev_end = 0
    for hostname in _find_hostnames.finditer(msg):
        ret += msg[prev_end : hostname.start()]
        ret += randhostname(hostname.groupdict()["hostname"])
        ret += msg[
            hostname.start() + len(hostname.groupdict()["hostname"]) : hostname.end()
        ]
        prev_end = hostname.end()
    ret += msg[prev_end:]
    return ret


def replace_certcn(msg):
    ret = msg
    prev_end = 0
    for certcn in _find_certcn.finditer(msg):
        cn = randcn(certcn.groupdict()["cn"])
        profname = randcertfn(certcn.groupdict()["cn"], certcn.groupdict()["profname"])
        ret = ret.replace(certcn.groupdict()["cn"], cn).replace(
            certcn.groupdict()["certfn"], profname
        )
    return ret


def replace_domain(msg):
    ret = msg
    for domain in _domains:
        ret = ret.replace(domain[0], domain[1])
    return ret


def replace_network(msg):
    if "boot_marker : ---===" in msg:
        return msg
    ret = ""
    prev_end = 0
    for ip_str in _find_ip_addresses.finditer(msg):
        try:
            ip = ip_address(ip_str.groupdict()["ip"])
        except ValueError:
            continue
        for net in _nets:
            if ip in net[0]:
                new_ip = randip(ip, net)
                ret += msg[prev_end : ip_str.start()]
                ret += str(new_ip)
                prev_end = ip_str.end()
                break
    ret += msg[prev_end:]
    return ret


# here we
replacers = [
    replace_hostnames,
    replace_certcn,
    replace_domain,
    replace_network,
]

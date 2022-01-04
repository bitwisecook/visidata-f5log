from collections import namedtuple
from ipaddress import ip_network, ip_address, IPv4Address, IPv6Address
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

NetMap = namedtuple("NetMap", ("orig_net", "map_net", "keep_ips"))

_nets = [
    NetMap(
        ip_network("10.0.0.0/8"),
        ip_network("10.0.0.0/8"),
        True,
    ),
    NetMap(
        ip_network("100.64.0.0/10"),
        ip_network("100.64.0.0/10"),
        True,
    ),
    NetMap(
        ip_network("127.0.0.0/8"),
        ip_network("127.0.0.0/8"),
        False,
    ),
    NetMap(
        ip_network("169.254.0.0/16"),
        ip_network("169.254.0.0/16"),
        True,
    ),
    NetMap(
        ip_network("172.16.0.0/12"),
        ip_network("172.16.0.0/12"),
        True,
    ),
    NetMap(
        ip_network("192.0.0.0/24"),
        ip_network("192.0.0.0/24"),
        True,
    ),
    NetMap(
        ip_network("192.0.2.0/24"),
        ip_network("192.0.2.0/24"),
        True,
    ),
    NetMap(
        ip_network("192.88.99.0/24"),
        ip_network("192.88.99.0/24"),
        True,
    ),
    NetMap(
        ip_network("192.168.0.0/16"),
        ip_network("192.168.0.0/16"),
        True,
    ),
    NetMap(
        ip_network("198.18.0.0/15"),
        ip_network("198.18.0.0/15"),
        True,
    ),
    NetMap(
        ip_network("198.51.100.0/24"),
        ip_network("198.51.100.0/24"),
        True,
    ),
    NetMap(
        ip_network("203.0.113.0/24"),
        ip_network("203.0.113.0/24"),
        True,
    ),
    NetMap(
        ip_network("224.0.0.0/4"),
        ip_network("224.0.0.0/4"),
        True,
    ),
    NetMap(
        ip_network("233.252.0.0/24"),
        ip_network("233.252.0.0/24"),
        True,
    ),
    NetMap(
        ip_network("240.0.0.0/4"),
        ip_network("240.0.0.0/4"),
        True,
    ),
    NetMap(
        ip_network("255.255.255.255/32"),
        ip_network("255.255.255.255/32"),
        True,
    ),
    NetMap(
        ip_network("::/128"),
        ip_network("::/128"),
        False,
    ),
    NetMap(
        ip_network("::1/128"),
        ip_network("::1/128"),
        True,
    ),
    NetMap(
        ip_network("::/112"),
        ip_network("::/112"),
        False,
    ),
    NetMap(
        ip_network("::ffff:0:0/96"),
        ip_network("::ffff:0:0/96"),
        True,
    ),
    NetMap(
        ip_network("::ffff:0:0:0/96"),
        ip_network("::ffff:0:0:0/96"),
        True,
    ),
    NetMap(
        ip_network("64:ff9b::/96"),
        ip_network("64:ff9b::/96"),
        True,
    ),
    NetMap(
        ip_network("64:ff9b:1::/48"),
        ip_network("64:ff9b:1::/48"),
        True,
    ),
    NetMap(
        ip_network("100::/64"),
        ip_network("100::/64"),
        True,
    ),
    NetMap(
        ip_network("2001:0000::/32"),
        ip_network("2001:0000::/32"),
        True,
    ),
    NetMap(
        ip_network("2001:20::/28"),
        ip_network("2001:20::/28"),
        True,
    ),
    NetMap(
        ip_network("2001:db8::/32"),
        ip_network("2001:db8::/32"),
        True,
    ),
    NetMap(
        ip_network("2002::/16"),
        ip_network("2002::/16"),
        True,
    ),
    NetMap(
        ip_network("fc00::/7"),
        ip_network("fc00::/7"),
        True,
    ),
    NetMap(
        ip_network("fe80::/10"),
        ip_network("fe80::/10"),
        True,
    ),
    NetMap(
        ip_network("ff00::/8"),
        ip_network("ff00::/8"),
        True,
    ),
    NetMap(
        ip_network("107.162.0.0/16"),
        ip_network("203.24.0.0/16"),
        True,
    ),
    NetMap(
        ip_network("2604:e180:82::/48"),
        ip_network("11f:32a0:17::/48"),
        True,
    ),
    NetMap(
        ip_network("2604:e180:83::/48"),
        ip_network("11f:32a0:37ab::/48"),
        True,
    ),
    NetMap(
        ip_network("2604:e180::/32"),
        ip_network("11f:32a0::/32"),
        True,
    ),
]

# for ip overwriting we find by list order
# so the specific ones above take precedence
for n in range(0, 255):
    _nets.append(
        NetMap(
            ip_network(f"{n}.0.0.0/8"),
            ip_network(f"{random.randrange(1,230)}.0.0.0/8"),
            False,
        )
    )

for n in range(0, 0xFF):
    _nets.append(
        NetMap(
            ip_network(f"{n:x}00::/8"),
            ip_network(
                f"{random.randrange(0,255):x}{random.randrange(0,255):x}:{random.randrange(0,255):x}{random.randrange(0,255):x}::/32"
            ),
            False,
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


def randipv4(ip, net):
    global _rand_ipv4
    if ip not in _rand_ipv4:
        if not net.keep_ips and net.map_net.num_addresses > 2:
            offset = random.randrange(1, net.map_net.num_addresses - 2)
        else:
            offset = 0
        _rand_ipv4[ip] = str(
            IPv4Address(
                int(ip)
                - int(net.orig_net.network_address)
                + int(net.map_net.network_address)
                + offset
            )
        )
    return _rand_ipv4[ip]


def randipv6(ip, net):
    global _rand_ipv6
    if ip not in _rand_ipv6:
        if not net.keep_ips and net.map_net.num_addresses > 2:
            offset = random.randrange(1, net.map_net.num_addresses - 2)
        else:
            offset = 0
        _rand_ipv6[ip] = str(
            IPv6Address(
                int(ip)
                - int(net.orig_net.network_address)
                + int(net.map_net.network_address)
                + offset
            )
        )
    return _rand_ipv6[ip]


def randip(ip, net):
    if ip_address(ip).version == 4:
        return randipv4(ip, net)
    return randipv6(ip, net)


def replace_hostnames(msg, logrow):
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


def replace_certcn(msg, logrow):
    ret = msg
    prev_end = 0
    for certcn in _find_certcn.finditer(msg):
        cn = randcn(certcn.groupdict()["cn"])
        profname = randcertfn(certcn.groupdict()["cn"], certcn.groupdict()["profname"])
        ret = ret.replace(certcn.groupdict()["cn"], cn).replace(
            certcn.groupdict()["certfn"], profname
        )
    return ret


def replace_domain(msg, logrow):
    ret = msg
    for domain in _domains:
        ret = ret.replace(domain[0], domain[1])
    return ret


def replace_network(msg, logrow):
    if all([_ in msg for _ in ("---===[ ", " ]===---")]) or logrow.logid1 in (
        "01010001",
        "01070711",
        "0107165d",
        "0107d000",
        "012b0000",
        "012b0021",
    ):
        return msg
    ret = ""
    prev_end = 0
    for ip_str in _find_ip_addresses.finditer(msg):
        ipg, port = ip_str.groupdict()["ip"], None
        if logrow.logid1 in ("01070151", "01220001", "010716ac") and ipg in (
            "0::",
            "::",
        ):
            continue
        # ipv6 with colon based port, why oh why would you be such a lazy prat
        # when forming these log messages?
        if (
            logrow.logid1
            in (
                "01230140",
                "01070638",
                "01070727",
                "01070728",
                "01071038",
                "01260026",
                "011ae0f2",
            )
            or (logrow.message and logrow.message.startswith("mprov"))
        ):
            if len(ipg.split(":")) > 2:
                ipg, port = ipg.rsplit(":", maxsplit=1)
        try:
            ip = ip_address(ipg)
        except ValueError:
            continue
        for net in _nets:
            if ip in net[0]:
                new_ip = randip(ip, net)
                ret += msg[prev_end : ip_str.start()]
                ret += str(new_ip)
                if port is not None:
                    ret += f":{port}"
                prev_end = ip_str.end()
                break
    ret += msg[prev_end:]
    return ret


# here we list out the replacers to execute and what order to run them in
replacers = [
    replace_hostnames,
    replace_certcn,
    replace_domain,
    replace_network,
]

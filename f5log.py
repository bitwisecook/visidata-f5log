from datetime import datetime, timedelta
from functools import partial
from ipaddress import ip_address
import re
from typing import Any, Dict, Optional

from visidata import Path, VisiData, Sheet, date, ColumnAttr, vd

hexint = partial(int, base=16)
delta_t = partial(int, base=10)
re_f5log = re.compile(
    r"^(?:\<\d+\>\s+)?(?:(?P<date1>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})|(?P<date2>\d+-\d+-\d+T\d+:\d+:\d+[+-]\d+:\d+))\s+(?P<host>[a-z0-9_.]+)\s+(?:(?P<level>[a-z]+)\s+(?:(?P<process>[a-z0-9_()-]+\s?)\[(?P<pid>\d+)\]:\s+)?(?:(?P<logid1>[0-9a-f]{8}):(?P<logid2>[0-9a-f]):\s+)?)?(?P<message>.*)$"
)
re_ltm_irule = re.compile(
    r"(?:(?P<irule_msg>TCL\serror|Rule|Pending\srule):?\s(?P<irule>\S+)\s\<(?P<event>[A-Z_0-9]+)\>(?:\s-\s|:\s|\s)?)(?P<message>aborted\sfor\s(?P<src_ip>\S+)\s->\s(?P<dst_ip>\S+)|.*)"
)
re_ag_objname = re.compile(
    r"(?:/Common/(?P<customer_id>[a-z0-9_]{1,23})-(?:\1-)?(?P<proxy_id>\d+)(?:_(?P<service_id>\d+)\.app/)?)"
)
re_ltm_pool_mon_status_msg = re.compile(
    r"^Pool\s(?P<poolobj>\S+)\smember\s(?P<poolmemberobj>\S+)\smonitor\sstatus\s(?P<newstatus>\w+)\.\s\[\s(?P<monitorobj>\S+):\s(?P<monitorstatus>\w+)(?:;\slast\serror:\s\S*\s?(?P<lasterr>.*))?\s]\s+\[\swas\s(?P<prevstatus>\w+)\sfor\s(?P<durationhr>\d+)hrs?:(?P<durationmin>\d+)mins?:(?P<durationsec>\d+)sec\s\]$"
)
re_ltm_ip_msg = re.compile(
    r"(?:.*?)(?P<ip1>\d+\.\d+\.\d+\.\d+)(?:[:.](?P<port1>\d+))?(?:(?:\s->\s|:)(?P<ip2>\d+\.\d+\.\d+\.\d+)(?:[:.](?P<port2>\d+))?)?(?:\smonitor\sstatus\s(?P<mon_status>\w+)\.\s\[[^]]+\]\s+\[\swas\s(?P<prev_status>\w+)\sfor\s((?P<durationhr>\d+)hrs?:(?P<durationmin>\d+)mins?:(?P<durationsec>\d+)secs?)\s\]|\.?(?:.*))"
)
re_ltm_conn_error = re.compile(
    r"^Connection\serror:\s(?P<func>[^:]+):(?P<funcloc>[^:]+):\s(?P<error>.*)\s\((?P<errno>\d+)\)$"
)
re_ltm_cert_expiry = re.compile(
    r"Certificate\s'(?P<cert_cn>.*)'\sin\sfile\s(?P<file>\S+)\s(?P<message>will\sexpire|expired)\son\s(?P<date1>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s\d+\s\S+)"
)
re_gtm_monitor = re.compile(
    r"^(?:SNMP_TRAP:\s)?(?P<objtype>VS|Pool|Monitor|Wide\sIP|Server)\s(?P<object>\S+)\s(?:member\s(?P<pool_member>\S+)\s)?(?:\(ip(?::port)?=(?P<ipport>[^\)]+)\)\s)?(?:\(Server\s(?P<server>[^\)]+)\)\s)?(?:state\schange\s)?(?P<prev_status>\w+)\s-->\s(?P<new_status>\w+)(?:(?:\s\(\s?)(?P<msg>(?:(?P<type>\w+)\s(?P<monitor_object>\S+)\s:\s)?state:\s(?P<state>\S+)|.*)\))?"
)

vd.addType(ip_address, icon=":", formatter=lambda fmt, ip: str(ip))
vd.addType(hexint, icon="ⓧ", formatter=lambda fmt, num: hex(num))
vd.addType(
    delta_t,
    icon="⇥",
    formatter=lambda fmt, delta: str(timedelta(seconds=delta)),
)


class F5LogSheet(Sheet):
    class F5LogRow:
        def __init__(
            self,
            msg: str = None,
            date_time: datetime = None,
            host: str = None,
            level: str = None,
            process: str = None,
            pid: int = None,
            logid1: hexint = None,
            logid2: hexint = None,
            message: str = None,
            kv: Optional[Dict[str, Any]] = None,
            **kwargs,
        ):
            self._data = {
                "msg": msg,
                "date_time": date_time,
                "host": host,
                "level": level,
                "process": process,
                "pid": pid,
                "logid1": logid1,
                "logid2": logid2,
                "message": message,
                "kv": kv,
                **kwargs,
            }

        def __getattr__(self, item):
            return self._data.get(item)

    rowtype = "logs"

    columns = [
        ColumnAttr("rawmsg", type=str),
        ColumnAttr("date_time", type=date),
        ColumnAttr("host", type=str),
        ColumnAttr("level", type=str),
        ColumnAttr("process", type=str),
        ColumnAttr("pid", type=int),
        ColumnAttr("logid1", type=hexint),  # hexint
        ColumnAttr("logid2", type=hexint),  # hexint
        ColumnAttr("message", type=str),
    ]

    @staticmethod
    def split_audit_01420002(msg):
        # skip 'AUDIT - ' at the start of the line
        e = msg[8:].split("=", maxsplit=6)

        for ee, ne in zip(e, e[1:]):
            yield {ee[ee.rfind(" ") + 1 :]: ne[: ne.rfind(" ")]}

    @staticmethod
    def split_audit_014F0005(msg):
        # skip 'AUDIT - ' at the start of the line
        e = msg[8:].split("=")

        for ee, ne in zip(e, e[1:]):
            yield {ee[ee.rfind(" ") + 1 :]: ne[: ne.rfind(" ")].strip('"')}

    @staticmethod
    def split_audit_01070417(msg):
        # skip 'AUDIT - ' at the start of the line
        # skip the status at the end of the line
        if msg[msg.rfind("[Status=") :].startswith("[Status="):
            e = msg[8 : msg.rfind("[Status=") - 1].split(" - ")
            status = msg[msg.rfind("[Status=") + 1 : -1]
            yield {
                status.split("=", maxsplit=1)[0]: status.split("=", maxsplit=1)[1],
            }
        else:
            e = msg[8:].split(" - ")
            status = None

        for ee in e[0].split(","):
            ee = ee.strip().split(" ")
            # yield the kvs in the first bit split on ,
            if ee[0].startswith("tmsh-pid-"):
                # of course tmsh-pid- is different
                yield {ee[0][: ee[0].rfind("-")]: int(ee[0][ee[0].rfind("-") + 1 :])}
            else:
                yield {ee[0]: ee[1]}

        for ee in e[1:]:
            ee = ee.strip().split(" ", maxsplit=1)
            if ee[0] == "transaction":
                yield {"transaction": int(ee[1][1:].split("-")[0])}
                yield {"transaction_step": int(ee[1][1:].split("-")[1])}
            else:
                # yield the rest of the kvs
                try:
                    yield {ee[0]: ee[1]}
                except IndexError:
                    yield {ee[0]: None}

    @staticmethod
    def split_ltm_pool_mon_status(msg):
        m = re_ltm_pool_mon_status_msg.match(msg)
        if m is None:
            return
        m = m.groupdict()
        if m.get("durationhr") and m.get("durationmin") and m.get("durationsec"):
            duration = timedelta(
                hours=int(m.get("durationhr")),
                minutes=int(m.get("durationmin")),
                seconds=int(m.get("durationsec")),
            ).total_seconds()
        else:
            duration = None
        dst = m.get("poolmemberobj")
        if dst:
            dst = dst.split("/")[-1]
            if len(dst.split(":")) == 2:
                # ipv4
                dst_ip, dst_port = dst.split(":")
            else:
                # ipv6
                dst_ip, dst_port = dst.split(".")
            try:
                # see if it's an IP and if so parse it
                dst_ip = ip_address(dst_ip)
            except ValueError:
                dst_ip = None
            try:
                # see if it's a port number and if so parse it
                dst_port = int(dst_port)
            except ValueError:
                dst_port = None
        else:
            dst_ip, dst_port = None, None
        yield {
            "object": m.get("poolobj"),
            "pool_member": m.get("poolmemberobj"),
            "new_status": m.get("newstatus"),
            "monitor": m.get("monitorobj"),
            "monitor_status": m.get("monitorstatus"),
            "last_error": m.get("lasterr"),
            "prev_status": m.get("prevstatus"),
            "duration_s": duration,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
        }

    @staticmethod
    def split_ltm_pool_has_no_avail_mem(msg):
        yield {
            "object": msg.split(" ")[-1],
            "new_status": "no members available",
        }

    @staticmethod
    def split_ltm_pool_has_avail_mem(msg):
        yield {
            "object": msg.split(" ")[1],
            "new_status": "now has available members",
        }

    @staticmethod
    def split_ltm_rule(msg):
        m = re_ltm_irule.match(msg)
        if m is None:
            return
        m = m.groupdict()
        y = {
            "irule_msg": m.get("irule_msg"),
            "object": m.get("irule"),
            "event": m.get("event"),
            "message": m.get("message"),
        }
        if m.get("message", "").startswith("aborted for"):
            src = m.get("src_ip")
            if src and len(src.split(":")) == 2:
                # ipv4
                y["src_ip"], y["src_port"] = src.split(":")
            else:
                # ipv6
                y["src_ip"], y["src_port"] = src.split(".")
            dst = m.get("dst_ip")
            if dst and len(dst.split(":")) == 2:
                # ipv4
                y["dst_ip"], y["dst_port"] = dst.split(":")
            else:
                # ipv6
                y["dst_ip"], y["dst_port"] = dst.split(".")
        yield y

    @staticmethod
    def split_ltm_cert_expiry(msg):
        m = re_ltm_cert_expiry.match(msg)
        if m is None:
            return
        m = m.groupdict()
        yield {
            "cert_cn": m.get("cert_cn"),
            "object": m.get("file"),
            "date": datetime.strptime(
                m.get("date1").replace("  ", " "),
                "%b %d %H:%M:%S %Y %Z",
            )
            if m.get("date1") is not None
            else None,
            "message": m.get("message"),
        }

    @staticmethod
    def split_ltm_connection_error(msg):
        m = re_ltm_conn_error.match(msg)
        if m is None:
            return
        m = m.groupdict()
        yield {
            "func": m.get("func"),
            "funcloc": m.get("funcloc"),
            "error": m.get("error"),
            "errno": m.get("errno"),
        }

    @staticmethod
    def split_ltm_virtual_status(msg):
        m = msg.split(" ")
        if m[0] == "SNMP_TRAP:":
            yield {
                "object": m[2],
                "new_status": m[-1],
            }
        else:
            yield {
                "object": m[1],
                "new_status": m[-1],
            }

    @staticmethod
    def split_ltm_ssl_handshake_fail(msg):
        src = msg.split(" ")[5]
        if len(src.split(":")) == 2:
            # ipv4
            src_ip, src_port = src.split(":")
        else:
            # ipv6
            src_ip, src_port = src.split(".")
        dst = msg.split(" ")[7]
        if len(dst.split(":")) == 2:
            # ipv4
            dst_ip, dst_port = dst.split(":")
        else:
            dst_ip, dst_port = dst.split(".")
        yield {
            "src_ip": ip_address(src_ip),
            "src_port": int(src_port),
            "dst_ip": ip_address(dst_ip),
            "dst_port": int(dst_port),
        }

    @staticmethod
    def split_ltm_shared_ciphers(msg):
        m = msg.split(" ")[-1][:-1]
        src, dst = m.split(":")
        if len(src.split(".")) == 5:
            # ipv4
            src_ip, src_port = src[: src.rfind(".")], src[src.rfind(".") + 1 :]
        else:
            # ipv6
            src_ip, src_port = src[: src.rfind(".")], src[src.rfind(".") + 1 :]
        if len(dst.split(".")) == 5:
            # ipv4
            dst_ip, dst_port = dst[: dst.rfind(".")], dst[dst.rfind(".") + 1 :]
        else:
            dst_ip, dst_port = dst[: dst.rfind(".")], dst[dst.rfind(".") + 1 :]
        yield {
            "src_ip": ip_address(src_ip),
            "src_port": int(src_port),
            "dst_ip": ip_address(dst_ip),
            "dst_port": int(dst_port),
        }

    @staticmethod
    def split_ltm_rst_reason(msg):
        m = msg.split(" ", maxsplit=6)
        src, dst = m[3].strip(","), m[5].strip(",")
        if len(src.split(":")) == 2:
            # ipv4
            src_ip, src_port = src.split(":")
        else:
            # ipv6
            src_ip, src_port = src.split(".")
        if len(dst.split(":")) == 2:
            # ipv4
            dst_ip, dst_port = dst.split(":")
        else:
            dst_ip, dst_port = dst.split(".")
        yield {
            "src_ip": ip_address(src_ip),
            "src_port": int(src_port),
            "dst_ip": ip_address(dst_ip),
            "dst_port": int(dst_port),
            "rst_reason": m[6],
        }

    @staticmethod
    def split_gtm_monitor(msg):
        m = re_gtm_monitor.match(msg)
        if m is None:
            return
        m = m.groupdict()
        dst = m.get("ipport")
        if dst:
            if len(dst.split(".")) == 4:
                # ipv4
                if ":" in dst:
                    dst_ip, dst_port = dst.split(":")
                else:
                    dst_ip, dst_port = dst, None
            else:
                # ipv6
                if "." in dst:
                    dst_ip, dst_port = dst.split(".")
                else:
                    dst_ip, dst_port = dst, None
        else:
            dst_ip, dst_port = None, None
        yield {
            "objtype": m.get("objtype"),
            "object": m.get("object"),
            "pool_member": m.get("pool_member"),
            "dst_ip": ip_address(dst_ip) if dst_ip else None,
            "dst_port": int(dst_port) if dst_port else None,
            "server": m.get("server"),
            "prev_status": m.get("prev_status").lower()
            if m.get("prev_status")
            else None,
            "new_status": m.get("new_status").lower() if m.get("new_status") else None,
            "msg": m.get("msg"),
            "type": m.get("type"),
            "monitor_object": m.get("monitor_object"),
            "state": m.get("state"),
        }

    @staticmethod
    def split_gtm_monitor_instance(msg):
        m = msg.split(" ")
        dst = m[3]
        if dst:
            if len(dst.split(":")) == 2:
                # ipv4
                dst_ip, dst_port = dst.split(":")
            else:
                dst_ip, dst_port = dst.split(".")
        else:
            dst_ip, dst_port = None, None
        yield {
            "object": m[2],
            "dst_ip": ip_address(dst_ip) if dst_ip else None,
            "dst_port": int(dst_port) if dst_port else None,
            "prev_status": m[4].lower(),
            "new_status": m[6].lower(),
            "src_gtm": ip_address(m[8]),
            "state": m[10][:-1].lower(),
        }

    splitters = {
        0x01010028: split_ltm_pool_has_no_avail_mem.__func__,
        0x01010221: split_ltm_pool_has_avail_mem.__func__,
        0x01070417: split_audit_01070417.__func__,
        0x01070638: split_ltm_pool_mon_status.__func__,
        0x01070727: split_ltm_pool_mon_status.__func__,
        0x01071681: split_ltm_virtual_status.__func__,
        0x01071682: split_ltm_virtual_status.__func__,
        0x01071BA9: split_ltm_virtual_status.__func__,
        0x011A1004: split_gtm_monitor.__func__,
        0x011A1005: split_gtm_monitor.__func__,
        0x011A3003: split_gtm_monitor.__func__,
        0x011A3004: split_gtm_monitor.__func__,
        0x011A4002: split_gtm_monitor.__func__,
        0x011A4003: split_gtm_monitor.__func__,
        0x011A5003: split_gtm_monitor.__func__,
        0x011A5004: split_gtm_monitor.__func__,
        0x011A6005: split_gtm_monitor.__func__,
        0x011A6006: split_gtm_monitor.__func__,
        0x011AE0F2: split_gtm_monitor_instance.__func__,
        # 0x01220000: split_ltm_rule.__func__,
        0x01220001: split_ltm_rule.__func__,
        0x01220002: split_ltm_rule.__func__,
        # 0x01220003: split_ltm_rule.__func__,
        # 0x01220004: split_ltm_rule.__func__,
        # 0x01220005: split_ltm_rule.__func__,
        0x01220007: split_ltm_rule.__func__,
        0x01220008: split_ltm_rule.__func__,
        0x01220009: split_ltm_rule.__func__,
        0x01220010: split_ltm_rule.__func__,
        0x01220011: split_ltm_rule.__func__,
        # 0x01220012: split_ltm_rule.__func__,
        0x01230140: split_ltm_rst_reason.__func__,
        0x01260013: split_ltm_ssl_handshake_fail.__func__,
        0x01260026: split_ltm_shared_ciphers.__func__,
        0x01260008: split_ltm_connection_error.__func__,
        0x01260009: split_ltm_connection_error.__func__,
        0x01420002: split_audit_01420002.__func__,
        0x01420007: split_ltm_cert_expiry.__func__,
        0x01420008: split_ltm_cert_expiry.__func__,
        0x014F0005: split_audit_014F0005.__func__,
    }

    # these logs can have IDs we care about splitting but would be errors
    # the match is starts_with because of course some logs have extra dynamic junk
    no_split_logs = (
        "Per-invocation log rate exceeded; throttling",
        "Resuming log processing at this invocation",
        "Re-enabling general logging;",
        "Cumulative log rate exceeded!  Throttling all non-debug logs.",
    )

    extra_cols = {
        "rawmsg",
        "date_time",
        "host",
        "level",
        "process",
        "pid",
        "logid1",
        "logid2",
        "message",
    }

    def iterload(self):
        self.rows = []  # rowdef: [F5LogRow]

        # the default F5 logs don't have the year so we have to guess from the file ctime
        # TODO: make this overridable
        self._year = datetime.utcfromtimestamp(self.source.stat().st_ctime).strftime(
            "%Y"
        )

        for line in self.source:
            m = re_f5log.match(line)
            if m:
                m = m.groupdict()
            else:
                yield F5LogSheet.F5LogRow(
                    rawmsg=line, kv={"PARSE_ERROR": "unable to parse line"}
                )
                continue
            kv = {"message": m.get("message")}
            if m.get("date1"):
                timestamp = datetime.strptime(
                    f"{self._year} {m.get('date1').replace('  ', ' ')}",
                    "%Y %b %d %H:%M:%S",
                )
            elif m.get("date2"):
                timestamp = datetime.strptime(
                    m.get("date2").replace("+", "-"), "%Y-%m-%dT%H:%M:%S-%z"
                )

            logid1 = int(m.get("logid1"), base=16) if m.get("logid1") else None
            # logid2 = int(m.get("logid2"), base=16) if m.get("logid2") else None
            if logid1 in self.splitters and not any(
                m.get("message", "").startswith(_) for _ in F5LogSheet.no_split_logs
            ):
                try:
                    for entry in F5LogSheet.splitters[logid1](m.get("message")):
                        kv.update(entry)
                except (IndexError, ValueError) as exc:
                    kv = {"PARSE_ERROR": str(exc)}
                for k, v in kv.items():
                    if k not in self.extra_cols:
                        F5LogSheet.addColumn(self, ColumnAttr(k))
                        self.extra_cols.add(k)
            elif logid1 is None and m.get("message").startswith("Rule "):
                for entry in self.split_ltm_rule(m.get("message")):
                    kv.update(entry)
            yield F5LogSheet.F5LogRow(
                # rawmsg=line,
                date_time=timestamp,
                host=m.get("host"),
                level=m.get("level"),
                process=m.get("process"),
                pid=int(m.get("pid")) if m.get("pid") is not None else None,
                logid1=m.get("logid1") if m.get("logid1") is not None else None,
                logid2=m.get("logid2") if m.get("logid2") is not None else None,
                # message=m.get("message"),
                # kv=kv,
                **kv,
            )


@VisiData.api
def open_f5log(vd: VisiData, p: Path) -> Sheet:
    sheet = F5LogSheet(p.name, source=p)
    sheet.options["disp_date_fmt"] = "%Y-%m-%d %H:%M:%S"
    return sheet

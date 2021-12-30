__name__ = "f5log"
__author__ = "James Deucker <me@bitwisecook.org>"
__version__ = "0.3.3"

from datetime import datetime, timedelta
from functools import partial
from ipaddress import ip_address
import re
import traceback
from typing import Any, Dict, Optional

from visidata import Path, VisiData, Sheet, date, ColumnAttr, vd, theme
from visidata.column import Column
from visidata.sheets import CellColorizer, RowColorizer


class hexint(int):
    def __new__(cls, value, *args, **kwargs):
        return super(cls, cls).__new__(cls, value, base=16)

    def __str__(self):
        return hex(self)


class delta_t(int):
    def __new__(cls, value, *args, **kwargs):
        return super(cls, cls).__new__(cls, value, base=10)


vd.addType(ip_address, icon=":", formatter=lambda fmt, ip: str(ip))
vd.addType(hexint, icon="ⓧ", formatter=lambda fmt, num: str(num))
vd.addType(
    delta_t,
    icon="⇥",
    formatter=lambda fmt, delta: str(timedelta(seconds=delta)),
)
theme("color_f5log_mon_up", "green", "color of f5log monitor status up")
theme("color_f5log_mon_down", "red", "color of f5log monitor status down")
theme("color_f5log_mon_unknown", "blue", "color of f5log monitor status unknown")
theme("color_f5log_mon_checking", "magenta", "color of monitor status checking")
theme("color_f5log_mon_disabled", "black", "color of monitor status disabled")
theme(
    "color_f5log_logid_warning", "red", "color of something urgent to pay attention to"
)
vd.option(
    "f5log_object_regex",
    None,
    "A regex to perform on the object name, useful where object names have a structure to extract. Use the (?P<foo>...) named groups form to get column names.",
)


class F5LogSheet(Sheet):
    class F5LogRow:
        def __init__(
            self,
            msg: str = None,
            timestamp: datetime = None,
            host: str = None,
            level: str = None,
            process: str = None,
            proc_pid: int = None,
            logid1: hexint = None,
            logid2: hexint = None,
            message: str = None,
            kv: Optional[Dict[str, Any]] = None,
            **kwargs,
        ):
            self._data = {
                "msg": msg,
                "timestamp": timestamp,
                "host": host,
                "level": level,
                "process": process,
                "proc_pid": proc_pid,
                "logid1": logid1,
                "logid2": logid2,
                "message": message,
                "kv": kv,
                **kwargs,
            }

        def __getattr__(self, item):
            return self._data.get(item)

    # strptime is slow so we we need to parse manually
    _months = {
        "Jan": 1,
        "Feb": 2,
        "Mar": 3,
        "Apr": 4,
        "May": 5,
        "Jun": 6,
        "Jul": 7,
        "Aug": 8,
        "Sep": 9,
        "Oct": 10,
        "Nov": 11,
        "Dec": 12,
    }

    rowtype = "logs"

    columns = [
        ColumnAttr("rawmsg", type=str),
        ColumnAttr("timestamp", type=date),
        ColumnAttr("host", type=str),
        ColumnAttr("level", type=str),
        ColumnAttr("process", type=str),
        ColumnAttr("proc_pid", type=int),
        ColumnAttr("logid1", type=hexint),
        ColumnAttr("logid2", type=hexint),
        ColumnAttr("message", type=str),
        ColumnAttr("object", type=str),
    ]

    re_f5log = re.compile(
        r"^(?:\<\d+\>\s+)?(?:(?P<date1>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})|(?P<date2>\d+-\d+-\d+T\d+:\d+:\d+[+-]\d+:\d+))\s+(?P<host>[a-z0-9_./]+)\s+(?:(?P<level>[a-z]+)\s+(?:(?P<process>[a-z0-9_()-]+\s?)\[(?P<pid>\d+)\]:\s+)?(?:(?P<logid1>[0-9a-f]{8}):(?P<logid2>[0-9a-f]):\s+)?)?(?P<message>.*)$"
    )
    re_ltm_irule = re.compile(
        r"(?:(?P<irule_msg>TCL\serror|Rule|Pending\srule):?\s(?P<irule>\S+)\s\<(?P<event>[A-Z_0-9]+)\>(?:\s-\s|:\s|\s)?)(?P<message>aborted\sfor\s(?P<srchost>\S+)\s->\s(?P<dsthost>\S+)|.*)"
    )
    re_ltm_pool_mon_status_msg = re.compile(
        r"^(Pool|Node)\s(?P<poolobj>\S+)\s(member|address)\s(?P<poolmemberobj>\S+)\smonitor\sstatus\s(?P<newstatus>.+)\.\s\[\s((?P<monitorobj>\S+):\s(?P<monitorstatus>\w+)(?:;\slast\serror:\s\S*\s?(?P<lasterr>.*))?)?\s]\s+\[\swas\s(?P<prevstatus>.+)\sfor\s(?P<durationhr>\d+)hrs?:(?P<durationmin>\d+)mins?:(?P<durationsec>\d+)sec\s\]$"
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
    re_gtm_monitor_instance = re.compile(
        r"^Monitor\sinstance\s(?P<object>\S+)\s(?P<monip>\S+)\s(?P<prevstatus>\S+)\s-->\s(?P<newstatus>\S+)\sfrom\s(?P<srcgtm>\S+)\s\((?:state:?\s)?(?P<state>.*)\)"
    )
    re_ltm_poolnode_abled = re.compile(
        r"^(?P<objtype>Pool|Node)\s(?P<object>\S+)\s(?:address|member)\s(?P<member>\S+)\ssession\sstatus\s(?P<status>.+)\.$"
    )
    re_ltm_no_shared_ciphers = re.compile(
        r"^(?P<msg>No\sshared\sciphers\sbetween\sSSL\speers)\s(?P<srchost>\d+\.\d+\.\d+\.\d+|[0-9a-f:]+)\.(?P<srcport>\d+)\:(?P<dsthost>\d+\.\d+\.\d+\.\d+|[0-9a-f:]+)\.(?P<dstport>\d+)\.$"
    )

    f5log_mon_colors = {
        ("monitor_status", "down"): "color_f5log_mon_down",
        ("monitor_status", "up"): "color_f5log_mon_up",
        ("monitor_status", "enabled"): "color_f5log_mon_up",
        ("monitor_status", "forced disabled"): "color_f5log_mon_disabled",
        ("monitor_status", "node disabled"): "color_f5log_mon_disabled",
        ("new_status", "available"): "color_f5log_mon_up",
        ("new_status", "unavailable"): "color_f5log_mon_down",
        ("new_status", "up"): "color_f5log_mon_up",
        ("new_status", "down"): "color_f5log_mon_down",
        ("new_status", "green"): "color_f5log_mon_up",
        ("new_status", "red"): "color_f5log_mon_down",
        ("new_status", "now has available members"): "color_f5log_mon_up",
        ("new_status", "no members available"): "color_f5log_mon_down",
        ("new_status", "blue"): "color_f5log_mon_unknown",
        ("new_status", "checking"): "color_f5log_mon_checking",
        ("new_status", "unchecked"): "color_f5log_mon_unknown",
        ("new_status", "node down"): "color_f5log_mon_disabled",
        ("prev_status", "available"): "color_f5log_mon_up",
        ("prev_status", "unavailable"): "color_f5log_mon_down",
        ("prev_status", "up"): "color_f5log_mon_up",
        ("prev_status", "down"): "color_f5log_mon_down",
        ("prev_status", "green"): "color_f5log_mon_up",
        ("prev_status", "red"): "color_f5log_mon_down",
        ("prev_status", "now has available members"): "color_f5log_mon_up",
        ("prev_status", "no members available"): "color_f5log_mon_down",
        ("prev_status", "blue"): "color_f5log_mon_unknown",
        ("prev_status", "checking"): "color_f5log_mon_checking",
        ("prev_status", "unchecked"): "color_f5log_mon_unknown",
        ("prev_status", "node down"): "color_f5log_mon_disabled",
    }

    def colorizeMonitors(sheet, col: Column, row: F5LogRow, value):
        if row is None or col is None:
            return None
        return sheet.f5log_mon_colors.get((col.name, value.value), None)

    f5log_warn_logid = {"01190004": "color_f5log_logid_warning"}

    def colorizeWarnings(sheet, col: Column, row: F5LogRow, value):
        if row is None or col is None:
            return None
        return sheet.f5log_warn_logid.get(row.logid1, None)

    @staticmethod
    def split_audit_bigip_tmsh_audit(msg):
        # skip 'AUDIT - ' at the start of the line
        e = msg[8:].split("=", maxsplit=6)

        for ee, ne in zip(e, e[1:]):
            yield {ee[ee.rfind(" ") + 1 :]: ne[: ne.rfind(" ")]}

    @staticmethod
    def split_audit_scriptd_run_script(msg):
        # skip 'AUDIT - ' at the start of the line
        e = msg[8:].split("=")

        for ee, ne in zip(e, e[1:]):
            yield {ee[ee.rfind(" ") + 1 :]: ne[: ne.rfind(" ")].strip('"')}

    @staticmethod
    def split_audit_mcpd_mcp_error(msg):
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
            elif len(ee) == 1:
                yield {ee[0]: None}
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
        m = F5LogSheet.re_ltm_pool_mon_status_msg.match(msg)
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
            if "." in dst and len(dst.split(":")) == 2:
                # ipv4
                dsthost, dstport = dst.split(":")
            elif "." in dst and len(dst.split(":")) == 1:
                # ipv4
                dsthost, dstport = dst, None
            else:
                # ipv6
                dsthost, dstport = dst.rsplit(":", maxsplit=1)
            try:
                # see if it's an IP and if so parse it
                dsthost = ip_address(dsthost)
            except ValueError:
                dsthost = None
            try:
                # see if it's a port number and if so parse it
                dstport = int(dstport)
            except (ValueError, TypeError):
                dstport = None
        else:
            dsthost, dstport = None, None
        yield {
            "object": m.get("poolobj"),
            "pool_member": m.get("poolmemberobj"),
            "new_status": m.get("newstatus"),
            "monitor": m.get("monitorobj"),
            "monitor_status": m.get("monitorstatus"),
            "last_error": m.get("lasterr"),
            "prev_status": m.get("prevstatus"),
            "duration_s": duration,
            "dsthost": dsthost,
            "dstport": dstport,
        }

    @staticmethod
    def split_ltm_poolnode_mon_abled(msg):
        m = F5LogSheet.re_ltm_poolnode_abled.match(msg)
        if m is None:
            return
        m = m.groupdict()
        yield {
            "object": m.get("object"),
            "member": m.get("member"),
            "monitor_status": m.get("status"),
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
        m = F5LogSheet.re_ltm_irule.match(msg)
        if m is None:
            return
        m = m.groupdict()
        yield {
            "irule_msg": m.get("irule_msg"),
            "object": m.get("irule"),
            "irule_event": m.get("event"),
            "msg": m.get("message"),
        }
        if m.get("message", "").startswith("aborted for"):
            src = m.get("srchost")
            if src and len(src.split(":")) == 2:
                # ipv4
                srchost, srcport = src.split(":")
            else:
                # ipv6
                srchost, srcport = src.split(".")
            dst = m.get("dsthost")
            if dst and len(dst.split(":")) == 2:
                # ipv4
                dsthost, dstport = dst.split(":")
            else:
                # ipv6
                dsthost, dstport = dst.split(".")
            yield {
                "srchost": ip_address(srchost),
                "srcport": int(srcport),
                "dsthost": ip_address(dsthost),
                "dstport": int(dstport),
            }

    @staticmethod
    def split_ltm_cert_expiry(msg):
        m = F5LogSheet.re_ltm_cert_expiry.match(msg)
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
        m = F5LogSheet.re_ltm_conn_error.match(msg)
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
            srchost, srcport = src.split(":")
        else:
            # ipv6
            srchost, srcport = src.split(".")
        dst = msg.split(" ")[7]
        if len(dst.split(":")) == 2:
            # ipv4
            dsthost, dstport = dst.split(":")
        else:
            dsthost, dstport = dst.split(".")
        yield {
            "srchost": ip_address(srchost),
            "srcport": int(srcport),
            "dsthost": ip_address(dsthost),
            "dstport": int(dstport),
        }

    @staticmethod
    def split_ltm_shared_ciphers(msg):
        m = F5LogSheet.re_ltm_no_shared_ciphers.match(msg)
        if m is None:
            return
        m = m.groupdict()
        yield {
            "srchost": ip_address(m.get("srchost")),
            "srcport": int(m.get("srcport")),
            "dsthost": ip_address(m.get("dsthost")),
            "dstport": int(m.get("dstport")),
        }

    @staticmethod
    def split_ltm_rst_reason(msg):
        m = msg.split(" ", maxsplit=7)
        src, dst = m[3].strip(","), m[5].strip(",")
        reasonc1, reasonc2 = m[6].split(':')
        if len(src.split(":")) == 2:
            # ipv4
            srchost, srcport = src.split(":")
        else:
            # ipv6
            srchost, srcport = src.rsplit(".", maxsplit=1)
        if len(dst.split(":")) == 2:
            # ipv4
            dsthost, dstport = dst.split(":")
        else:
            dsthost, dstport = dst.rsplit(":", maxsplit=1)
        yield {
            "srchost": ip_address(srchost),
            "srcport": int(srcport),
            "dsthost": ip_address(dsthost),
            "dstport": int(dstport),
            "rst_reason_code1": hexint(reasonc1[3:]),
            "rst_reason_code2": hexint(reasonc2[:-1]),
            "rst_reason": m[7],
        }

    @staticmethod
    def split_gtm_monitor(msg):
        m = F5LogSheet.re_gtm_monitor.match(msg)
        if m is None:
            return
        m = m.groupdict()
        dst = m.get("ipport")
        if dst:
            if len(dst.split(".")) == 4:
                # ipv4
                if ":" in dst:
                    dsthost, dstport = dst.split(":")
                else:
                    dsthost, dstport = dst, None
            else:
                # ipv6
                if "." in dst:
                    dsthost, dstport = dst.rsplit(".", maxsplit=1)
                else:
                    dsthost, dstport = dst, None
        else:
            dsthost, dstport = None, None
        yield {
            "objtype": m.get("objtype").lower() if m.get("objtype") else None,
            "object": m.get("object"),
            "pool_member": m.get("pool_member"),
            "dsthost": ip_address(dsthost) if dsthost else None,
            "dstport": int(dstport) if dstport else None,
            "server": m.get("server"),
            "prev_status": m.get("prev_status").lower()
            if m.get("prev_status")
            else None,
            "new_status": m.get("new_status").lower() if m.get("new_status") else None,
            "msg": m.get("msg"),
            "type": m.get("type").lower() if m.get("type") in m else None,
            "monitor_object": m.get("monitor_object"),
            "state": m.get("state"),
        }

    @staticmethod
    def split_gtm_monitor_instance(msg):
        m = F5LogSheet.re_gtm_monitor_instance.match(msg)
        if m is None:
            return
        m = m.groupdict()
        if m.get("monip"):
            if len(m.get("monip").split(":")) == 2:
                # ipv4
                dsthost, dstport = m.get("monip").split(":")
            else:
                dsthost, dstport = m.get("monip").rsplit(":", maxsplit=1)
        else:
            dsthost, dstport = None, None
        yield {
            "object": m.get("object"),
            "dsthost": ip_address(dsthost) if dsthost else None,
            "dstport": int(dstport) if dstport else None,
            "prev_status": m.get("prevstatus", "").lower(),
            "new_status": m.get("newstatus", "").lower(),
            "src_gtm": m.get("srcgtm"),
            "state": m.get("state").lower(),
        }

    @staticmethod
    def split_tmm_address_conflict(msg):
        m = msg.split(" ")
        dsthost = m[4]
        yield {
            "dstmac": m[5].strip("()"),
            "dsthost": ip_address(dsthost),
            "object": m[7],
        }

    splitters = {
        0x01010028: split_ltm_pool_has_no_avail_mem.__func__,
        0x01010221: split_ltm_pool_has_avail_mem.__func__,
        0x01070417: split_audit_mcpd_mcp_error.__func__,
        0x01070638: split_ltm_pool_mon_status.__func__,
        0x01070639: split_ltm_poolnode_mon_abled.__func__,
        0x01070641: split_ltm_poolnode_mon_abled.__func__,
        0x01070727: split_ltm_pool_mon_status.__func__,
        0x01070728: split_ltm_pool_mon_status.__func__,
        0x01071681: split_ltm_virtual_status.__func__,
        0x01071682: split_ltm_virtual_status.__func__,
        0x01071BA9: split_ltm_virtual_status.__func__,
        0x01190004: split_tmm_address_conflict.__func__,
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
        0x01420002: split_audit_bigip_tmsh_audit.__func__,
        0x01420007: split_ltm_cert_expiry.__func__,
        0x01420008: split_ltm_cert_expiry.__func__,
        0x014F0005: split_audit_scriptd_run_script.__func__,
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
        "timestamp",
        "host",
        "level",
        "process",
        "proc_pid",
        "logid1",
        "logid2",
        "message",
        "object",
    }

    # precedence, coloropt, func
    colorizers = [
        CellColorizer(100, None, colorizeMonitors),
        RowColorizer(101, None, colorizeWarnings),
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # the default F5 logs don't have the year so we have to guess from the file ctime
        # TODO: make this overridable
        try:
            self._year = datetime.utcfromtimestamp(self.source.stat().st_ctime).year
        except AttributeError:
            self._year = datetime.now().year

    def iterload(self):
        self.rows = []  # rowdef: [F5LogRow]

        if vd.options.get("f5log_object_regex"):
            try:
                object_regex = re.compile(vd.options.get("f5log_object_regex"))
            except re.error as exc:
                # TODO: make this error into the errors sheet
                object_regex = None
        else:
            object_regex = None

        for line in self.source:
            m = F5LogSheet.re_f5log.match(line)
            if m:
                m = m.groupdict()
            else:
                # TODO: somehow make this use an error sheet
                yield F5LogSheet.F5LogRow(
                    rawmsg=line, kv={"PARSE_ERROR": "unable to parse line"}
                )
                continue
            kv = {
                "message": m.get("message"),
            }
            if m.get("date1"):
                #
                _t = m.get("date1")
                # strptime is quite slow so we need to manually extract the time on the hot path
                try:
                    timestamp = datetime(
                        year=self._year,
                        month=self._months[_t[:3]],
                        day=int(_t[4:6]),
                        hour=int(_t[7:9]),
                        minute=int(_t[10:12]),
                        second=int(_t[13:15]),
                    )
                except ValueError as exc:
                    yield F5LogSheet.F5LogRow(
                        rawmsg=line,
                        PARSE_ERROR="\n".join(
                            traceback.format_exception(
                                etype=type(exc), value=exc, tb=exc.__traceback__
                            ),
                        ),
                    )
            elif m.get("date2"):
                timestamp = datetime.strptime(m.get("date2"), "%Y-%m-%dT%H:%M:%S%z")
            else:
                timestamp = None

            logid1 = int(m.get("logid1"), base=16) if m.get("logid1") else None
            if logid1 in self.splitters and not any(
                m.get("message", "").startswith(_) for _ in F5LogSheet.no_split_logs
            ):
                try:
                    for entry in F5LogSheet.splitters[logid1](m.get("message")):
                        kv.update(entry)
                except (IndexError, ValueError) as exc:
                    # TODO: somehow make this use an error sheet
                    yield F5LogSheet.F5LogRow(
                        rawmsg=line,
                        PARSE_ERROR="\n".join(
                            traceback.format_exception(
                                etype=type(exc), value=exc, tb=exc.__traceback__
                            )
                        ),
                    )
                if "object" in kv and object_regex:
                    om = object_regex.match(kv.get("object", ""))
                    if om:
                        kv.update(om.groupdict())
                for k, v in kv.items():
                    if k not in self.extra_cols:
                        F5LogSheet.addColumn(self, ColumnAttr(k))
                        self.extra_cols.add(k)
            elif logid1 is None and m.get("message").startswith("Rule "):
                for entry in self.split_ltm_rule(m.get("message")):
                    kv.update(entry)
            yield F5LogSheet.F5LogRow(
                # rawmsg=line,
                timestamp=timestamp,
                host=m.get("host"),
                level=m.get("level"),
                process=m.get("process"),
                proc_pid=int(m.get("pid")) if m.get("pid") is not None else None,
                logid1=m.get("logid1") if m.get("logid1") is not None else None,
                logid2=m.get("logid2") if m.get("logid2") is not None else None,
                **kv,
            )


@VisiData.api
def open_f5log(vd: VisiData, p: Path) -> Sheet:
    sheet = F5LogSheet(p.name, source=p)
    sheet.options["disp_date_fmt"] = "%Y-%m-%d %H:%M:%S"
    return sheet

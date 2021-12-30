from ipaddress import ip_address
from f5log import F5LogSheet
import traceback
import gzip
import sys
import gentests_replacers

f5log = F5LogSheet()

logkeys = set()


class LineRememberer:
    def __init__(self, f):
        self._f = f
        self.prev_last_line = ""
        self.last_line = ""
        self.linenum = 0

    def __iter__(self):
        for self.linenum, l in enumerate(self._f.readlines()):
            self.prev_last_line = self.last_line
            self.last_line = l
            yield l


def replace_msg(msg):
    ret=msg
    for replacer in gentests_replacers.replacers:
        ret = replacer(ret)
    return ret

def parse_lines(f, logkeys, logs):
    ls = F5LogSheet()
    # patch the year to be one with a leap year
    ls._year = 2020
    ls.source = LineRememberer(f)
    try:
        for line in ls.iterload():
            if line.PARSE_ERROR:
                logs.write(replace_msg(ls.source.last_line))
                continue
            if line.logid1 is None:
                if line.message.split(" ")[0].split(".")[0] not in logkeys:
                    logs.write(replace_msg(ls.source.last_line))
                    logkeys.add(line.message.split(" ")[0].split(".")[0])
                    continue
            k = (
                line.logid1,
                line.objtype,
                line.prev_status,
                line.new_status,
                line.type,
                line.srchost.version if line.srchost else None,
                line.dsthost.version if line.dsthost else None,
                str(type(line.srcport)) if line.srcport else None,
                str(type(line.dstport)) if line.dstport else None,
                line.type,
                line.rst_reason,
                line.irule_msg,
                line.PARSE_ERROR,
                "|".join(line._data.keys()),
                "|".join(line._data["kv"].keys()) if line._data["kv"] else None,
            )
            if k in logkeys:
                continue
            print(k)
            logkeys.add(k)
            logs.write(replace_msg(ls.source.last_line))
    except Exception as exc:
        logs.write(replace_msg(ls.source.prev_last_line))
        logs.write(replace_msg(ls.source.last_line))
        print("--- ERROR ---")
        print(
            "\n".join(
                traceback.format_exception(
                    etype=type(exc), value=exc, tb=exc.__traceback__
                )
            )
        )
        print("---")
        print(ls.source.linenum)
        print(ls.source.prev_last_line)
        print(ls.source.last_line)
        print("--- ERROR ---")


with open(sys.argv[1], "w") as logs:
    for fn in sys.argv[2:]:
        l = len(logkeys)
        print(f"parsing {fn}", flush=True)
        gz = False
        try:
            with gzip.open(fn, "rt", encoding="utf8", errors="backslashreplace") as f:
                f.read(1)
                gz = True
        except gzip.BadGzipFile:
            pass
        except IsADirectoryError:
            print(f"{fn} is a directory")
            continue

        if gz:
            with gzip.open(fn, "rt", encoding="utf8", errors="backslashreplace") as f:
                parse_lines(f, logkeys=logkeys, logs=logs)
        else:
            with open(fn, "r", encoding="utf8", errors="backslashreplace") as f:
                parse_lines(f, logkeys=logkeys, logs=logs)

        print(f"found {len(logkeys) - l} more logs")
        logs.flush()

print(f"wrote {len(logkeys)} logs to test file {sys.argv[1]}")

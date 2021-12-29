from ipaddress import ip_address
from f5log import F5LogSheet
import traceback
import gzip
import sys

f5log = F5LogSheet()

logbin = {}


class LineRememberer:
    def __init__(self, f):
        self._f = f
        self.last_line = ""

    def __iter__(self):
        for l in self._f.readlines():
            self.last_line = l
            yield l


def parse_lines(f):
    ret = {}
    ls = F5LogSheet()
    ls.source = LineRememberer(f)
    for line in ls.iterload():
        if line.PARSE_ERROR:
            print(line)
            print(line.PARSE_ERROR)
        k = (
            line.logid1,
            line.objtype,
            line.prev_status,
            line.new_status,
            line.type,
            line.srchost.version if line.srchost else None,
            line.dsthost.version if line.dsthost else None,
            line.type,
        )
        if k in ret:
            continue
        print(k)
        ret[k] = ls.source.last_line
    return ret


for fn in sys.argv[2:]:
    l = len(logbin)
    print(f"parsing {fn}", flush=True)
    try:
        with gzip.open(fn, "rt", encoding="utf8") as f:
            logbin.update(parse_lines(f))
    except gzip.BadGzipFile:
        with open(fn, "r", encoding="utf8") as f:
            logbin.update(parse_lines(f))
    print(f"found {len(logbin) - l} more logs")

with open(sys.argv[1], "w") as tf:
    for k, l in logbin.items():
        tf.write(l)
print(f"wrote test file {sys.argv[1]}")

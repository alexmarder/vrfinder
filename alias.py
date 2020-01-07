from collections import defaultdict
from typing import Set

from traceutils.file2.file2 import File2
from traceutils.progress.bar import Progress
from traceutils.radix.ip2as import IP2AS


class Alias:

    def __init__(self, filename, ip2as: IP2AS, include: Set[str] = None, increment=500000):
        self.filename = filename
        nodes = defaultdict(set)
        aliases = {}
        pb = Progress(message='Reading aliases', increment=increment, callback=lambda: 'Found {:,d} Addrs {:,d}'.format(len(nodes), len(aliases)))
        with File2(filename) as f:
            for line in pb.iterator(f):
                line = line.strip()
                if not line:
                    continue
                if line[0] == '#':
                    continue
                _, nid, *addrs = line.split()
                if include is not None:
                    if not any(a in include for a in addrs):
                        continue
                addrs = {a for a in addrs if not -100 < ip2as[a] < 0}
                if not addrs:
                    continue
                nid = nid[:-1]
                nodes[nid] = set(addrs)
                for addr in addrs:
                    aliases[addr] = nid
        self.node = dict(nodes)
        self.nid = dict(aliases)

    def aliases(self, addr):
        nid = self.nid.get(addr)
        if nid is not None:
            return self.node[self.nid[addr]]
        return set()

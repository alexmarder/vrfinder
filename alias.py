from collections import defaultdict
from typing import Set

from traceutils.file2.file2 import File2
from traceutils.progress.bar import Progress


class Alias:

    def __init__(self, filename, include: Set[str] = None):
        self.filename = filename
        nodes = defaultdict(set)
        aliases = {}
        pb = Progress(message='Reading aliases', increment=100000, callback=lambda: 'Found {:,d}'.format(len(nodes)))
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
                nid = nid[:-1]
                nodes[nid] = set(addrs)
                for addr in addrs:
                    aliases[addr] = nid
        self.node = dict(nodes)
        self.nid = dict(aliases)

    def aliases(self, addr):
        return self.node[self.nid[addr]]

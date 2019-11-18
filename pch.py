import os

from traceutils.file2.file2 import File2
from traceutils.progress.bar import Progress
from traceutils.radix.ip2as import IP2AS

class PCH:
    def __init__(self, ip2as: IP2AS):
        self.ip2as = ip2as

    def read(self, file):
        addrs = {}
        with File2(file) as f:
            for line in f:
                if line.startswith('*'):
                    try:
                        _, net, addr, metric, weight, *path = line.split()
                    except:
                        continue
                    path = path[:-1]
                    if not path:
                        continue
                    if '/' not in net:
                        continue
                    try:
                        asn = int(path[0])
                        if asn != 42 and asn != 715:
                            if self.ip2as[addr] <= -100:
                                # addrs[addr] = (asn, os.path.basename(file))
                                if addr not in addrs:
                                    addrs[addr] = asn
                    except:
                        print(line)
                        raise
        return addrs

    def read_files(self, files, addrs=None):
        if addrs is None:
            addrs = {}
        pb = Progress(len(files), 'pch', increment=1, callback=lambda: '{:,d}'.format(len(addrs)))
        for file in pb.iterator(files):
            newaddrs = self.read(file)
            addrs.update(newaddrs)
        return addrs

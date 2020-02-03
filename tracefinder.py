#!/usr/bin/env python
import json
import os
from argparse import ArgumentParser
from collections import Counter
from multiprocessing.pool import Pool
from random import sample
from socket import AF_INET6
from typing import List, Union, Optional

from traceutils.file2.file2 import File2
from traceutils.ixps import AbstractPeeringDB, create_peeringdb
from traceutils.progress.bar import Progress
from traceutils.radix.ip2as import IP2AS, create_table
from traceutils.scamper.hop import Hop, ICMPType
from traceutils.scamper.warts import WartsReader
from traceutils.utils.net import inet_fix

from finder_info import FinderInfo, FinderInfoContainer

_ip2as: Optional[IP2AS] = None

class FakeHop:
    addr = None
    reply_ttl = None

def are_adjacent(b1, b2):
    return b1[:-1] == b2[:-1] and abs(b1[-1] - b2[-1]) == 1

def same_prefix(x: str, y: str, prefixlen):
    xprefix = inet_fix(AF_INET6, x.encode(), prefixlen)
    yprefix = inet_fix(AF_INET6, y.encode(), prefixlen)
    return xprefix == yprefix

def select_w(trace, i, xaddr):
    w: Hop = trace.hops[i - 1]
    if w.addr == xaddr:
        for j in range(i - 2, -2, -1):
            if j < 0:
                return FakeHop()
            w = trace.hops[j]
            if w.addr != xaddr:
                return w
    return w

def valid_pair(b1, b2):
    r1 = b1[-1] % 4
    r2 = b2[-1] % 4
    if r1 == 0:
        return 2 if r2 == 1 else 0
    elif r1 == 1:
        return -2 if r2 == 0 else 4
    elif r1 == 2:
        return -4 if r2 == 1 else 2
    else:
        return -2 if r2 == 2 else 0

class WartsFile:
    def __init__(self, filename, monitor):
        self.filename = filename
        self.monitor = monitor

    def __repr__(self):
        return 'Warts<{}, {}>'.format(self.filename, self.monitor)

# def candidates_parallel_vp(filenames: List[WartsFile], output, ip2as=None, poolsize=35):
#     global _ip2as
#     if ip2as is not None:
#         _ip2as = ip2as
#     traces = 0
#     files = [wf.filename for wf in filenames]
#     pb = Progress(len(filenames), message='Reading files by VP', callback=lambda: '{:,d}'.format(traces))
#     with Pool(poolsize) as pool, File2(output, 'wt') as f:
#         for wf, newtraces in pb.iterator(zip(filenames, pool.imap(candidates, files))):
#             for t in newtraces:
#                 t['vp'] = wf.monitor
#                 j = json.dumps(t)
#                 f.write(j + '\n')
#             traces += len(newtraces)
#     return traces

def candidates_parallel_vp(filenames: List[WartsFile], ip2as=None, poolsize=35):
    global _ip2as
    if ip2as is not None:
        _ip2as = ip2as
    vps = {wf.monitor for wf in filenames}
    traces = {vp: [] for vp in vps}
    ntraces = 0
    files = [wf.filename for wf in filenames]
    pb = Progress(len(filenames), message='Reading files by VP', callback=lambda: '{:,d}'.format(ntraces))
    with Pool(poolsize) as pool:
        for wf, newtraces in pb.iterator(zip(filenames, pool.imap(candidates, files))):
            traces[wf.monitor].extend(newtraces)
            ntraces += len(newtraces)
    return traces

def candidates(filename: str, ip2as=None):
    global _ip2as
    if ip2as is not None:
        _ip2as = ip2as
    traces = []
    with WartsReader(filename) as f:
        for trace in f:
            if not trace.hops: continue
            trace.prune_private(_ip2as)
            if not trace.hops: continue
            packed = [hop.set_packed() for hop in trace.hops]
            for i in range(len(packed) - 1):
                b1 = packed[i]
                b2 = packed[i+1]
                if b1 == b2:
                    continue
                x = trace.hops[i]
                y = trace.hops[i+1]
                if x.probe_ttl == y.probe_ttl - 1:
                    xasn = _ip2as.asn_packed(b1)
                    if xasn >= 0:
                        if are_adjacent(b1, b2):
                            size = valid_pair(b1, b2)
                            if size == 2 or size == -2 or size == 4 or size == -4:
                                traces.append(trace.jdata)
                                break
                    elif xasn <= -100 and xasn == _ip2as.asn_packed(b2):
                        traces.append(trace.jdata)
                        break
    return traces

_addrs = None
_directory = None

def create_ixp_table(peeringdb: AbstractPeeringDB):
    table = IP2AS()
    table.add_private()
    ixp_prefixes = [(prefix, asn) for prefix, asn in peeringdb.prefixes.items() if not table.search_best_prefix(prefix)]
    for prefix, ixp_id in ixp_prefixes:
        table.add_asn(prefix, asn=(-100 - ixp_id))
    return table

def read_files(file):
    files = []
    with File2(file) as f:
        for line in f:
            line = line.strip()
            monitor = os.path.basename(line).partition('.')[0]
            wf = WartsFile(line, monitor)
            files.append(wf)
    return files

def main(argv=None):
    parser = ArgumentParser()
    parser.add_argument('-f', '--filename', required=True)
    parser.add_argument('-o', '--output', required=True)
    parser.add_argument('-p', '--poolsize', type=int, default=40)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--ip2as')
    group.add_argument('-I', '--peeringdb')
    parser.add_argument('--vp', action='store_true')
    args = parser.parse_args(args=argv)
    files = read_files(args.filename)
    print('Files: {:,d}'.format(len(files)))
    if args.peeringdb:
        peeringdb = create_peeringdb(args.peeringdb)
        ip2as = create_ixp_table(peeringdb)
    else:
        ip2as = create_table(args.ip2as)
    func = candidates_parallel_vp if args.vp else candidates_parallel_vp
    directory = os.path.dirname(args.output)
    if directory:
        os.makedirs(directory, exist_ok=True)
    traces = func(files, ip2as=ip2as, poolsize=args.poolsize)
    with File2(args.output, 'wt') as f:
        for trace in traces:
            j = json.dumps(trace)
            f.write(j + '\n')
    # func(files, args.output, ip2as=ip2as, poolsize=args.poolsize)

if __name__ == '__main__':
    main()

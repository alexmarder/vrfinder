#!/usr/bin/env python
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
middle_only = False
include_dsts = None

class FakeHop:
    addr = None
    reply_ttl = None

def add_pair(info: FinderInfo, ptype: int, w: Union[Hop, FakeHop], x: Hop, y: Hop, end: bool, dst: str):
    if ptype == 2 or ptype == -2:
        echo_cfas = info.echotwos
        middle_cfas = info.middletwos
        last_cfas = info.lasttwos
    elif ptype == 4 or ptype == -4:
        echo_cfas = info.echofours
        middle_cfas = info.middlefours
        last_cfas = info.lastfours
    else:
        return
    if end:
        if y.type == ICMPType.echo_reply:
            echo_cfas[x.addr] += 1
        else:
            if y.type == ICMPType.spoofing:
                info.spoofing.add(x.addr)
            else:
                info.nounreach.add(x.addr)
            last_cfas[x.addr] += 1
    else:
        middle_cfas[x.addr] += 1
    info.rttls[w.addr, x.addr, y.addr, w.reply_ttl, x.reply_ttl, y.reply_ttl] += 1
    info.triplets.add((w.addr, x.addr, y.addr))
    info.dsts.add((x.addr, y.addr, dst))

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

def candidates_parallel_vp(filenames: List[WartsFile], ip2as=None, poolsize=35):
    global _ip2as
    if ip2as is not None:
        _ip2as = ip2as
    infos = FinderInfoContainer.default()
    files = [wf.filename for wf in filenames]
    pb = Progress(len(filenames), message='Reading files by VP')
    with Pool(poolsize) as pool:
        for wf, newinfo in pb.iterator(zip(filenames, pool.imap(candidates, files))):
            infos[wf.monitor].update(newinfo)
    return infos

def candidates_parallel(filenames: List[WartsFile], ip2as=None, poolsize=35):
    global _ip2as
    if ip2as is not None:
        _ip2as = ip2as
    info = FinderInfo()
    files = [wf.filename for wf in filenames]
    pb = Progress(len(filenames), message='', callback=info.__str__)
    with Pool(poolsize) as pool:
        for wf, newinfo in pb.iterator(zip(filenames, pool.imap(candidates, files))):
            info.update(newinfo)
    return info

def candidates(filename: str, ip2as=None, info: FinderInfo = None):
    global _ip2as
    if ip2as is not None:
        _ip2as = ip2as
    if info is None:
        info = FinderInfo()
    with WartsReader(filename) as f:
        for trace in f:
            # if include_dsts is not None and trace.dst not in include_dsts: continue
            if not trace.hops: continue
            trace.prune_private(_ip2as)
            if not trace.hops: continue
            trace.prune_loops(keepfirst=True)
            if not trace.hops: continue
            if trace.loop:
                for x, y in zip(trace.loop, trace.loop[1:]):
                    info.loops[x.addr, y.addr] += 1
            packed = [hop.set_packed() for hop in trace.hops]
            for i in range(len(packed) - (1 if not middle_only else 2)):
                b1 = packed[i]
                b2 = packed[i+1]
                if b1 == b2:
                    continue
                x = trace.hops[i]
                y = trace.hops[i+1]
                w: Union[Hop, FakeHop] = select_w(trace, i, x.addr)
                info.middle[x.addr] += 1
                if x.probe_ttl == y.probe_ttl - 1:
                    if x.type == ICMPType.time_exceeded and (y.addr != trace.dst or y.type == ICMPType.time_exceeded or y.type == ICMPType.echo_reply):
                        xasn = _ip2as.asn_packed(b1)
                        if xasn >= 0:
                            if are_adjacent(b1, b2):
                                size = valid_pair(b1, b2)
                                add_pair(info=info, ptype=size, w=w, x=x, y=y, end=i+2 == len(packed), dst=trace.dst)
                        elif xasn <= -100 and xasn == _ip2as.asn_packed(b2):
                            wasn = _ip2as.asn_packed(packed[i-1]) if i > 0 else None
                            info.ixps.add((wasn, x.addr, y.addr))
                            info.ixp_adjs[x.addr, y.addr] += 1
                            info.triplets.add((w.addr, x.addr, y.addr))
            if not middle_only:
                x = trace.hops[-1]
                if x.type != ICMPType.echo_reply:
                    info.last[x.addr] += 1
    return info

_addrs = None
_directory = None

def write_addrs_vp(vp, directory=None, addrs=None):
    global _addrs, _directory
    if directory is not None:
        directory = _directory
    if addrs is not None:
        addrs = _addrs
    shuffled = sample(addrs, len(addrs))
    with open(os.path.join(directory, '{}.addrs'.format(vp)), 'w') as f:
        f.writelines('{}\n'.format(a) for a in shuffled)

def write_addrs(addrs, directory, vps):
    global _addrs, _directory
    _addrs = addrs
    _directory = directory
    os.makedirs(directory, exist_ok=True)
    pb = Progress(len(vps), 'Writing')
    for vp in pb.iterator(vps):
        write_addrs_vp(vp, directory, addrs)

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
    global middle_only, include_dsts
    parser = ArgumentParser()
    parser.add_argument('-f', '--filename', required=True)
    parser.add_argument('-o', '--output', required=True)
    parser.add_argument('-p', '--poolsize', type=int, default=40)
    parser.add_argument('-m', '--middle-only', action='store_true', help='For experiment purposes.')
    parser.add_argument('-d', '--include-dsts', help='For debugging purposes.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--ip2as')
    group.add_argument('-I', '--peeringdb')
    parser.add_argument('--vp', action='store_true')
    args = parser.parse_args(args=argv)
    middle_only = args.middle_only
    if args.include_dsts:
        with File2(args.include_dsts) as f:
            include_dsts = {line.strip() for line in f}
    files = read_files(args.filename)
    print('Files: {:,d}'.format(len(files)))
    if args.peeringdb:
        peeringdb = create_peeringdb(args.peeringdb)
        ip2as = create_ixp_table(peeringdb)
    else:
        ip2as = create_table(args.ip2as)
    func = candidates_parallel_vp if args.vp else candidates_parallel
    info = func(files, ip2as=ip2as, poolsize=args.poolsize)
    directory = os.path.dirname(args.output)
    if directory:
        os.makedirs(directory, exist_ok=True)
    info.dump(args.output)

if __name__ == '__main__':
    main()

#!/usr/bin/env python
import os
from argparse import ArgumentParser
from collections import Counter
from dataclasses import dataclass
from multiprocessing.pool import Pool
from random import sample
from socket import AF_INET6
from typing import List, Union, Optional, NamedTuple

from traceutils.file2.file2 import File2
from traceutils.progress.bar import Progress
from traceutils.radix.ip2as import IP2AS, create_table
from traceutils.scamper.hop import Hop, ICMPType
from traceutils.scamper.warts import WartsReader
from traceutils.utils.net import inet_fix

from candidate_info import CandidateInfo

_ip2as: Optional[IP2AS] = None
middle_only = False
include_dsts = None

class FakeHop:
    addr = None
    reply_ttl = None

def add_pair(info: CandidateInfo, ptype: int, w: Union[Hop, FakeHop], x: Hop, y: Hop, end: bool, dst: str):
    if ptype == 2 or ptype == -2:
        cfas: Counter = info.twos
        echo_cfas = info.echotwos
    elif ptype == 4 or ptype == -4:
        cfas: Counter = info.fours
        echo_cfas = info.echofours
    else:
        return
    cfas[x.addr] += 1
    info.rttls.add((w.addr, x.addr, y.addr, w.reply_ttl, x.reply_ttl, y.reply_ttl))
    info.triplets.add((w.addr, x.addr, y.addr))
    info.dst_asns.add((x.addr, _ip2as[dst]))
    if not end or y.type == ICMPType.echo_reply:
        echo_cfas.add(x.addr)
    if y.type == ICMPType.dest_unreach:
        info.unreach.add(x.addr)
    elif y.type == ICMPType.spoofing:
        info.spoofing.add(x.addr)
    else:
        info.nounreach.add(x.addr)

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

def candidates_parallel(filenames: List[WartsFile], ip2as=None, poolsize=35):
    global _ip2as
    if ip2as is not None:
        _ip2as = ip2as
    info = CandidateInfo()
    files = [wf.filename for wf in filenames]
    pb = Progress(len(filenames), message='', callback=info.__str__)
    with Pool(poolsize) as pool:
        for wf, newinfo in pb.iterator(zip(filenames, pool.imap(candidates, files))):
            info.update(newinfo)
    return info

def candidates(filename: str, ip2as=None, info: CandidateInfo = None):
    global _ip2as
    if ip2as is not None:
        _ip2as = ip2as
    if info is None:
        info = CandidateInfo()
    with WartsReader(filename) as f:
        for trace in f:
            if include_dsts is not None and trace.dst not in include_dsts:
                continue
            # info.dsts.add(trace.dst)
            if trace.hops:
                trace.prune_private(_ip2as)
                if trace.hops:
                    trace.prune_loops()
                    if trace.hops:
                        if trace.loop:
                            info.cycles.add(tuple(h.addr for h in trace.loop))
                            for x, y in zip(trace.loop, trace.loop[1:]):
                                info.loops[x, y] += 1
                        packed = [hop.set_packed() for hop in trace.hops]
                        for i in range(len(packed) - (1 if not middle_only else 2)):
                            b1 = packed[i]
                            b2 = packed[i+1]
                            if b1 == b2:
                                continue
                            x = trace.hops[i]
                            y = trace.hops[i+1]
                            w: Union[Hop, FakeHop] = select_w(trace, i, x.addr)
                            if x.probe_ttl == y.probe_ttl - 1:
                                xasn = _ip2as.asn_packed(b1)
                                if xasn >= 0:
                                    if are_adjacent(b1, b2):
                                        size = valid_pair(b1, b2)
                                        add_pair(info, size, w, x, y, i+2 == len(packed), trace.dst)
                                elif xasn <= -100 and xasn == _ip2as.asn_packed(b2):
                                    wasn = _ip2as.asn_packed(packed[i-1]) if i > 0 else None
                                    info.ixps.add((wasn, x.addr, y.addr))
                                    info.ixp_adjs[x.addr, y.addr] += 1
                                    info.triplets.add((w.addr, x.addr, y.addr))
                                if y.type == ICMPType.echo_reply:
                                    info.nextecho.add(x.addr)
                                else:
                                    info.nexthop.add(x.addr)
                            else:
                                if y.type == ICMPType.echo_reply:
                                    info.multiecho.add(x.addr)
                                else:
                                    info.multi.add(x.addr)
                        if not middle_only:
                            x = trace.hops[-1]
                            if x.type == ICMPType.echo_reply:
                                info.echos.add(x.addr)
                            else:
                                info.last.add(x.addr)
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

def main():
    global middle_only, include_dsts
    parser = ArgumentParser()
    parser.add_argument('-f', '--filename', required=True)
    parser.add_argument('-o', '--output', required=True)
    parser.add_argument('-i', '--ip2as', required=True)
    parser.add_argument('-p', '--poolsize', type=int, default=40)
    parser.add_argument('-m', '--middle-only', action='store_true', help='For experiment purposes.')
    parser.add_argument('-d', '--include-dsts', help='For debugging purposes.')
    args = parser.parse_args()
    middle_only = args.middle_only
    if args.include_dsts:
        with File2(args.include_dsts) as f:
            include_dsts = {line.strip() for line in f}
    files = []
    with File2(args.filename) as f:
        for line in f:
            line = line.strip()
            monitor = os.path.basename(line).partition('.')[0]
            wf = WartsFile(line, monitor)
            files.append(wf)
    print('Files: {:,d}'.format(len(files)))
    ip2as = create_table(args.ip2as)
    info = candidates_parallel(files, ip2as=ip2as, poolsize=args.poolsize)
    directory = os.path.dirname(args.output)
    if directory:
        os.makedirs(directory, exist_ok=True)
    info.dump(args.output, prune=True)

if __name__ == '__main__':
    main()

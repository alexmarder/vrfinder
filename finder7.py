#!/usr/bin/env python
import json
import os
import pickle
import subprocess
from argparse import ArgumentParser, FileType
from collections import defaultdict, Counter
from multiprocessing.pool import ThreadPool, Pool
from random import sample
from socket import AF_INET6, inet_pton, inet_ntop
from typing import List, Optional

from traceutils.file2.file2 import File2
from traceutils.progress.bar import Progress
from traceutils.radix.ip2as import IP2AS, create_table
from traceutils.scamper.hop import Hop, ICMPType
from traceutils.scamper.warts import WartsReader
from traceutils.utils.net import prefix_addrs, inet_fix

from candidate_info import CandidateInfo

_ip2as: IP2AS = None

def are_adjacent(b1, b2):
    i = 0
    for i in range(len(b1) - 1):
        if b1[i] != b2[i]:
            return False
    i += 1
    return abs(b1[i] - b2[i]) == 1

def same_prefix(x: str, y: str, prefixlen):
    xprefix = inet_fix(AF_INET6, x.encode(), prefixlen)
    yprefix = inet_fix(AF_INET6, y.encode(), prefixlen)
    return xprefix == yprefix

def valid_pair(b1, b2):
    r1 = b1[-1] % 4
    r2 = b2[-1] % 4
    if r1 == 0:
        if r2 == 1:
            return 2
        return 0
    elif r1 == 1:
        if r2 == 0:
            return -2
        return 4
    elif r1 == 2:
        if r2 == 1:
            return -4
        return 2
    else:
        if r2 == 2:
            return -2
        return 0

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
    pb = Progress(len(filenames), message='', callback=info.__repr__)
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
            if trace.hops:
                trace.prune_private(_ip2as)
                if trace.hops:
                    # trace.prune_dups()
                    trace.prune_loops()
                    if trace.loop:
                        info.cycles.add(tuple(h.addr for h in trace.loop))
                    packed = [hop.set_packed() for hop in trace.hops]
                    for i in range(len(packed) - 1):
                        b1 = packed[i]
                        b2 = packed[i+1]
                        if b1 == b2:
                            continue
                        x = trace.hops[i]
                        y = trace.hops[i+1]
                        xaddr = x.addr
                        yaddr = y.addr
                        w: Optional[Hop] = None
                        if i > 0:
                            w = trace.hops[i-1]
                            waddr = w.addr
                            if waddr == xaddr:
                                for j in range(i-2, -2, -1):
                                    if j < 0:
                                        w = None
                                        break
                                    w = trace.hops[j]
                                    if waddr != xaddr:
                                        break
                        if w is None:
                            waddr = None
                            wrttl = None
                        else:
                            waddr = w.addr
                            wrttl = w.reply_ttl
                        xasn = _ip2as.asn_packed(b1)
                        # if y.icmp_type != 0:
                        if x.probe_ttl == y.probe_ttl - 1:
                            # if not w or w.reply_ttl != y.reply_ttl:
                            if xasn >= 0:
                                if are_adjacent(b1, b2):
                                    size = valid_pair(b1, b2)
                                    if size != 0:
                                        if size == -2 or size == 2:
                                            info.twos.add(xaddr)
                                            info.rttls.add((waddr, xaddr, yaddr, wrttl, x.reply_ttl, y.reply_ttl))
                                            info.triplets.add((waddr, xaddr, yaddr))
                                            if y.type == ICMPType.echo_reply:
                                                info.echotwos.add(xaddr)
                                            if y.type == ICMPType.dest_unreach:
                                                info.unreach.add(xaddr)
                                            elif y.type == ICMPType.spoofing:
                                                info.spoofing.add(xaddr)
                                            else:
                                                info.nounreach.add(xaddr)
                                        elif size == -4 or size == 4:
                                            info.fours.add(xaddr)
                                            info.rttls.add((waddr, xaddr, yaddr, wrttl, x.reply_ttl, y.reply_ttl))
                                            info.triplets.add((waddr, xaddr, yaddr))
                                            if y.type == ICMPType.echo_reply:
                                                info.echofours.add(xaddr)
                                            if y.type == ICMPType.dest_unreach:
                                                info.unreach.add(xaddr)
                                            elif y.type == ICMPType.spoofing:
                                                info.spoofing.add(xaddr)
                                            else:
                                                info.nounreach.add(xaddr)
                            elif xasn <= -100 and xasn == _ip2as.asn_packed(b2):
                                if i > 0:
                                    wasn = _ip2as.asn_packed(packed[i-1])
                                else:
                                    wasn = None
                                info.ixps.add((wasn, xaddr, yaddr))
                                info.triplets.add((waddr, xaddr, yaddr))
                                # if y.type == ICMPType.dest_unreach:
                                #     info.unreach.add(xaddr)
                                # else:
                                #     info.nounreach.add(xaddr)
                        if x.probe_ttl == y.probe_ttl - 1:
                            if y.type == ICMPType.echo_reply:
                                info.nextecho.add(xaddr)
                            else:
                                info.nexthop.add(xaddr)
                        else:
                            if y.type == ICMPType.echo_reply:
                                info.multiecho.add(xaddr)
                            else:
                                info.multi.add(xaddr)
                        # info.tuples.add((xaddr, yaddr))
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

def write_addrs(addrs, directory, vps, poolsize=None):
    global _addrs, _directory
    _addrs = addrs
    _directory = directory
    os.makedirs(directory, exist_ok=True)
    # with Pool(poolsize) as pool:
    #     pb = Progress(len(vps), 'Writing')
    #     for _ in pb.iterator(pool.imap_unordered(write_addrs_vp, vps)):
    #         pass
    pb = Progress(len(vps), 'Writing')
    for vp in pb.iterator(vps):
        write_addrs_vp(vp, directory, addrs)

def main():
    parser = ArgumentParser()
    parser.add_argument('-f', '--filename', required=True)
    parser.add_argument('-o', '--output', required=True)
    parser.add_argument('-i', '--ip2as', required=True)
    parser.add_argument('-p', '--poolsize', type=int, default=40)
    args = parser.parse_args()
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
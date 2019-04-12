#!/usr/bin/env python
import json
import subprocess
from argparse import ArgumentParser, FileType
from collections import defaultdict, Counter
from multiprocessing.pool import ThreadPool, Pool
from typing import List

from traceutils.progress.bar import Progress
from traceutils.radix.ip2as import IP2AS
from traceutils.scamper.hop import Hop
from traceutils.scamper.warts import WartsReader
from traceutils.utils.net import prefix_addrs


_ip2as: IP2AS = None


def arksyncf(vps):
    return ','.join(sorted(vps))


def shmuxf(vps):
    return ' '.join(sorted(vps))


def are_adjacent(b1, b2):
    i = 0
    for i in range(len(b1) - 1):
        if b1[i] != b2[i]:
            return False
    i += 1
    return abs(b1[i] - b2[i]) == 1


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
    twos = set()
    fours = defaultdict(set)
    ixps = set()
    cycles = set()
    files = [wf.filename for wf in filenames]
    pb = Progress(len(filenames), message='Reading traceroutes', callback=lambda: 'Twos {:,d} Fours {:,d}'.format(len(twos), len(fours)))
    with Pool(poolsize) as pool:
        for wf, (newtwos, newfours, newixps, newcycles) in pb.iterator(zip(filenames, pool.imap(candidates, files))):
            twos.update(newtwos)
            # fours.update(newfours)
            for pair in newfours:
                fours[pair].add(wf.monitor)
            ixps.update(newixps)
            cycles.update(newcycles)
    return twos, fours


def candidates_sequential(filenames: List[WartsFile], ip2as=None):
    wf: WartsFile
    global _ip2as
    if ip2as is not None:
        _ip2as = ip2as
    twos = set()
    fours = defaultdict(set)
    pb = Progress(len(filenames), message='Reading traceroutes', callback=lambda: 'Twos {:,d} Fours {:,d}'.format(len(twos), len(fours)))
    for wf in pb.iterator(filenames):
        newtwos, newfours = candidates(wf.filename)
        twos.update(newtwos)
        for pair in newfours:
            fours[pair].add(wf.monitor)
    return twos, fours


# def candidates(filename: str, ip2as=None, twos=None, fours=None, ixps=None, cycles=None):
#     global _ip2as
#     if ip2as is not None:
#         _ip2as = ip2as
#     if twos is None:
#         twos = set()
#     if fours is None:
#         fours = set()
#     if ixps is None:
#         ixps = set()
#     if cycles is None:
#         cycles = set()
#     with WartsReader(filename) as f:
#         for trace in f:
#             trace.prune_dups()
#             trace.prune_loops()
#             # trace.prune_private()
#             packed = [hop.set_packed() for hop in trace.hops]
#             for i in range(len(packed) - 1):
#                 b1 = packed[i]
#                 if _ip2as.asn_packed(b1) >= 0:
#                     b2 = packed[i+1]
#                     if are_adjacent(b1, b2):
#                         size = valid_pair(b1, b2)
#                         if size != 0:
#                             pair = (trace.hops[i].addr, trace.hops[i+1].addr)
#                             if size == 2:
#                                 twos.add(pair)
#                             elif size == 4:
#                                 fours.add(pair)
#     return twos, fours


def candidates(filename: str, ip2as=None, twos=None, fours=None, ixps=None, cycles=None):
    global _ip2as
    if ip2as is not None:
        _ip2as = ip2as
    if twos is None:
        twos = set()
    if fours is None:
        fours = set()
    if ixps is None:
        ixps = set()
    if cycles is None:
        cycles = set()
    with WartsReader(filename) as f:
        for trace in f:
            seen = set()
            trace.prune_dups()
            hops = trace.hops
            packed = [hop.set_packed() for hop in hops]
            for i in range(len(packed) - 1):
                x: Hop = hops[i]
                bx = packed[i]
                xaddr = x.addr
                if xaddr in seen:
                    cycle = [(x.addr, x.reply_ttl)]
                    for j in range(i-1, -1, -1):
                        hop: Hop = hops[j]
                        cycle.insert(0, (hop.addr, hop.reply_ttl))
                        if packed[j] == bx:
                            cycles.add(tuple(cycle))
                            break
                    break
                seen.add(xaddr)
                y: Hop = hops[i+1]
                by = packed[i+1]
                xasn = _ip2as.asn_packed(bx)
                yasn = _ip2as.asn_packed(by)
                if xasn <= -100:
                    if xasn == yasn:
                        wasn = _ip2as.asn_packed(packed[i-1]) if i > 0 else 0
                        waddr = hops[i-1].addr if i > 0 else None
                        ixps.add((waddr, wasn, xaddr, y.addr))
                elif xasn > 0 and yasn > 0:
                    if are_adjacent(bx, by):
                        size = valid_pair(bx, by)
                        if size != 0:
                            pair = (trace.hops[i].addr, trace.hops[i+1].addr)
                            if size == 2:
                                twos.add(pair)
                            elif size == 4:
                                fours.add(pair)
    return twos, fours, ixps, cycles


def mplstest(filename, ip2as):
    bins = defaultdict(bool)
    test = defaultdict(set)
    with WartsReader(filename) as f:
        for trace in f:
            for i in range(len(trace.hops) - 2):
                x = trace.hops[i]
                if x.ismpls and ip2as[x.addr] in [11537, 11164]:
                    y = trace.hops[i+1]
                    z = trace.hops[i+2]
                    if x.probe_ttl == y.probe_ttl - 1 == z.probe_ttl - 2:
                        if x.addr == '162.252.70.144':
                            for hop in trace.hops:
                                print('{:02d}: {} {}'.format(hop.probe_ttl, hop.addr, hop.ismpls))
                            print()
                        test[x.addr].add((y.addr, z.addr))
                        if ip2as[x.addr] <= -100 and ip2as[y.addr] <= -100:
                            bins[x.addr] = True
                        if ip2as[y.addr] <= -100 and ip2as[z.addr] <= -100:
                            bins[x.addr] = True
                        else:
                            bins[x.addr] |= are_adjacent(x.set_packed(), y.set_packed())
                            bins[x.addr] |= are_adjacent(y.set_packed(), z.set_packed())
    return test, bins


def main():
    parser = ArgumentParser()
    parser.add_argument('-f', '--filename', required=True, type=FileType('r'))
    parser.add_argument('-o', '--output', required=True, type=FileType('w'))
    args = parser.parse_args()
    addrs = [line.strip() for line in args.filename]
    results = test_candidates(addrs)
    json.dump(results, args.output)


if __name__ == '__main__':
    main()

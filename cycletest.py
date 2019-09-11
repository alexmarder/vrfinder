#!/usr/bin/env python
import os
from argparse import ArgumentParser
from collections import defaultdict
from multiprocessing.pool import Pool
from os.path import basename
from typing import List, Dict

from traceutils.file2.file2 import File2
from traceutils.progress.bar import Progress
from traceutils.scamper.hop import ICMPType
from traceutils.scamper.warts import WartsReader
from traceutils.utils.net import otherside

from finder import are_adjacent, valid_pair


class CycleInfo:

    def __init__(self):
        self.fours = {}
        self.twos = {}

    def __repr__(self):
        return 'Twos {:,d} Fours {:,d}'.format(len(self.twos), len(self.fours))

    def badfour(self):
        return {a for a, b in self.fours.items() if not b}

    def update(self, info):
        update(self.fours, info.fours)
        update(self.twos, info.twos)


def update(old: Dict[str, bool], new: Dict[str, bool]):
    for addr, b in new.items():
        if not addr in old:
            old[addr] = b
        else:
            borig = old[addr]
            if b != borig:
                if not borig:
                    old[addr] = b


def candidates_parallel(files: List[str], poolsize=35):
    info = CycleInfo()
    pb = Progress(len(files), message='', callback=info.__repr__)
    with Pool(poolsize) as pool:
        for newinfo in pb.iterator(pool.imap(candidates, files)):
            info.update(newinfo)
    return info


def candidates(filename):
    info = CycleInfo()
    with WartsReader(filename) as f:
        for trace in f:
            dst = trace.dst
            dtwo = otherside(dst, 2)
            try:
                dfour = otherside(dst, 4)
            except:
                dfour = None
            # if trace.stop_reason == 'UNREACH':
            #     info.twos[dtwo] = False
            #     if dfour:
            #         info.fours[dfour] = False
            if trace.hops:
                if trace.stop_reason == 'COMPLETED':
                    if len(trace.hops) >= 2:
                        x = trace.hops[-2]
                        y = trace.hops[-1]
                        xaddr = x.addr
                        yaddr = y.addr
                        if yaddr == dst:
                            if xaddr == dfour:
                                info.fours[xaddr] = True
                            elif xaddr == dtwo:
                                info.twos[xaddr] = True
                else:
                    y = trace.hops[-1]
                    yaddr = y.addr
                    if yaddr == dfour:
                        info.fours[yaddr] = False
                    elif yaddr == dtwo:
                        info.twos[yaddr] = False
    return info


def pingparser_parallel(files: List[str], poolsize=35):
    responses = defaultdict(set)
    pb = Progress(len(files), message='', callback=lambda: '{:,d}'.format(len(responses)))
    with Pool(poolsize) as pool:
        for vp, newresponses in pb.iterator(pool.imap(pingparser, files)):
            for addr in newresponses:
                responses[addr].add(vp)
    return responses


def pingparser(filename):
    responses = []
    with WartsReader(filename) as f:
        for ping in f:
            resp = any(r.type == ICMPType.echo_reply for r in ping.responses)
            if resp:
                responses.append(ping.dst)
    return basename(filename).partition('.')[0], responses


def main():
    parser = ArgumentParser()
    parser.add_argument('-f', '--filename', required=True)
    parser.add_argument('-o', '--output', required=True)
    parser.add_argument('-p', '--poolsize', type=int, default=40)
    args = parser.parse_args()
    files = []
    with File2(args.filename) as f:
        for line in f:
            line = line.strip()
            files.append(line)
    print('Files: {:,d}'.format(len(files)))
    info = candidates_parallel(files, poolsize=args.poolsize)
    directory = os.path.dirname(args.output)
    if directory:
        os.makedirs(directory, exist_ok=True)
    info.dump(args.output, prune=True)


if __name__ == '__main__':
    main()

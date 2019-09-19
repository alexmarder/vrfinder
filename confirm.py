#!/usr/bin/env python
import os
from argparse import ArgumentParser
from collections import defaultdict
from multiprocessing.pool import Pool
from os.path import basename
from typing import List

from traceutils.file2.file2 import File2
from traceutils.progress.bar import Progress
from traceutils.scamper.hop import ICMPType
from traceutils.scamper.warts import WartsReader

from candidate_info import CandidateInfo
from finder import are_adjacent, valid_pair

class ConfirmInfo:
    def __init__(self):
        self.twos = set()
        self.fours = set()
        self.completed = set()

    def confirmed(self):
        return self.twos | self.fours

    def __repr__(self):
        return '2 {:,d} 4 {:,d} T {:,d} C {:,d}'.format(len(self.twos), len(self.fours), len(self.twos) + len(self.fours), len(self.completed))

    def update(self, info):
        self.twos.update(info.twos)
        self.fours.update(info.fours)
        self.completed.update(info.completed)

def candidates_parallel(files: List[str], poolsize=35):
    info = ConfirmInfo()
    pb = Progress(len(files), message='', callback=info.__repr__)
    with Pool(poolsize) as pool:
        for newinfo in pb.iterator(pool.imap(candidates, files)):
            info.update(newinfo)
    return info

def candidates(filename):
    info = ConfirmInfo()
    with WartsReader(filename) as f:
        for trace in f:
            if trace.stop_reason == 'COMPLETED':
                if len(trace.hops) >= 2:
                    x = trace.hops[-2]
                    y = trace.hops[-1]
                    xb = x.set_packed()
                    yb = y.set_packed()
                    info.completed.add(y.addr)
                    if are_adjacent(xb, yb):
                        size = valid_pair(xb, yb)
                        if size != 0:
                            if size == -2 or size == 2:
                                info.twos.add(x.addr)
                            elif size == -4 or size == 4:
                                info.fours.add(x.addr)
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

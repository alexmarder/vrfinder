#!/usr/bin/env python
import os
import pickle
from argparse import ArgumentParser
from collections import Counter, defaultdict
from multiprocessing.pool import Pool
from typing import List, Union, Optional

from traceutils.file2.file2 import File2
from traceutils.progress.bar import Progress
from traceutils.radix.ip2as import IP2AS, create_private
from traceutils.scamper.hop import Hop, ICMPType
from traceutils.scamper.warts import WartsReader

from finder import WartsFile, FakeHop, select_w

_ip2as: Optional[IP2AS] = None
middle_only = False
include_dsts = None

class NormalInfo:
    def __init__(self):
        self.adjs = Counter()
        self.loops = Counter()
        self.addrs = Counter()
        self.loopaddrs = Counter()

    def dump(self, filename):
        d = self.dumps()
        with open(filename, 'wb') as f:
            pickle.dump(d, f)

    def dumps(self):
        return {k: dict(v) for k, v in vars(self).items()}

    @classmethod
    def load(cls, filename):
        with open(filename, 'rb') as f:
            d = pickle.load(f)
        return cls.loads(d)

    @classmethod
    def loads(cls, d):
        info = cls()
        if not isinstance(d, dict):
            d = d.__dict__
        for k, v in d.items():
            getattr(info, k).update(v)
        return info

    def update(self, info):
        for k, v in vars(info).items():
            getattr(self, k).update(v)

class NormalInfoContainer(defaultdict):
    @classmethod
    def default(cls):
        return cls(NormalInfo)

    def dump(self, filename):
        d = {vp: info.dumps() for vp, info in self.items()}
        with open(filename, 'wb') as f:
            pickle.dump(d, f)

    @staticmethod
    def load(filename):
        with open(filename, 'rb') as f:
            infos = pickle.load(f)
        infos = {k: NormalInfo.loads(v) for k, v in infos.items()}
        return infos

def parse_parallel_vp(filenames: List[WartsFile], ip2as=None, poolsize=35):
    global _ip2as
    if ip2as is not None:
        _ip2as = ip2as
    infos = NormalInfoContainer.default()
    files = [wf.filename for wf in filenames]
    pb = Progress(len(filenames), message='Reading files by VP')
    with Pool(poolsize) as pool:
        for wf, newinfo in pb.iterator(zip(filenames, pool.imap(parse, files))):
            infos[wf.monitor].update(newinfo)
    return infos

def candidates_parallel(filenames: List[WartsFile], ip2as=None, poolsize=35):
    global _ip2as
    if ip2as is not None:
        _ip2as = ip2as
    info = NormalInfo()
    files = [wf.filename for wf in filenames]
    pb = Progress(len(filenames), message='', callback=info.__str__)
    with Pool(poolsize) as pool:
        for wf, newinfo in pb.iterator(zip(filenames, pool.imap(parse, files))):
            info.update(newinfo)
    return info

def parse(filename: str, ip2as=None, info: NormalInfo = None):
    global _ip2as
    if ip2as is not None:
        _ip2as = ip2as
    if info is None:
        info = NormalInfo()
    with WartsReader(filename) as f:
        for trace in f:
            if include_dsts is not None and trace.dst not in include_dsts: continue
            if not trace.hops: continue
            trace.prune_private(_ip2as)
            if not trace.hops: continue
            trace.prune_loops(keepfirst=True)
            if not trace.hops: continue
            info.addrs.update(trace.addrs())
            if trace.loop:
                info.loopaddrs.update(trace.loop)
                for x, y in zip(trace.loop, trace.loop[1:]):
                    info.loops[x.addr, y.addr] += 1
            for i in range(len(trace.hops) - (1 if not middle_only else 2)):
                x = trace.hops[i]
                y = trace.hops[i+1]
                w: Union[Hop, FakeHop] = select_w(trace, i, x.addr)
                if x.probe_ttl == y.probe_ttl - 1:
                    if x.type == ICMPType.time_exceeded and (y.addr != trace.dst or y.type == ICMPType.time_exceeded or y.type == ICMPType.echo_reply):
                        info.adjs[x.addr, y.addr] += 1
    return info

_addrs = None
_directory = None

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
    ip2as = create_private()
    func = parse_parallel_vp if args.vp else candidates_parallel
    info = func(files, ip2as=ip2as, poolsize=args.poolsize)
    directory = os.path.dirname(args.output)
    if directory:
        os.makedirs(directory, exist_ok=True)
    info.dump(args.output)

if __name__ == '__main__':
    main()

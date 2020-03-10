#!/usr/bin/env python
import os
import pickle
from argparse import ArgumentParser
from collections import defaultdict
from multiprocessing.pool import Pool
from typing import List, Optional

from traceutils.file2 import File2, fopen
from traceutils.progress.bar import Progress
from traceutils.radix.ip2as import create_private, IP2AS
from traceutils.scamper.warts import WartsReader

_ip2as: Optional[IP2AS] = None

def candidates_parallel(files: List[str], ip2as=None, poolsize=20):
    global _ip2as
    if ip2as is not None:
        _ip2as = ip2as
    tuples = set()
    pb = Progress(len(files), message='', callback=lambda: '{:,d}'.format(len(tuples)))
    with Pool(poolsize) as pool:
        for newinfo in pb.iterator(pool.imap(candidates, files)):
            tuples.update(newinfo)
    return tuples

def candidates(filename: str, ip2as=None):
    global _ip2as
    if ip2as is not None:
        _ip2as = ip2as
    info = set()
    with WartsReader(filename) as f:
        for trace in f:
            if not trace.hops: continue
            trace.prune_private(_ip2as)
            if not trace.hops: continue
            trace.prune_dups()
            if not trace.hops: continue
            trace.prune_loops(keepfirst=True)
            for i in range(len(trace.hops) - 1):
                x = trace.hops[i]
                y = trace.hops[i+1]
                info.add((x.addr, y.addr))
    return info

def read_files(file):
    files = []
    with File2(file) as f:
        for line in f:
            line = line.strip()
            files.append(line)
    return files

def toprevs(tuples):
    prevs = defaultdict(set)
    pb = Progress(len(tuples), 'Converting to prevs', increment=100000, callback=lambda: '{:,d}'.format(len(prevs)))
    for x, y in pb.iterator(tuples):
        prevs[y].add(x)
    return dict(prevs)

def main(argv=None):
    parser = ArgumentParser()
    parser.add_argument('-f', '--filename', required=True)
    parser.add_argument('-o', '--output', required=True)
    parser.add_argument('-p', '--poolsize', type=int, default=20)
    args = parser.parse_args(args=argv)
    files = read_files(args.filename)
    print('Files: {:,d}'.format(len(files)))
    ip2as = create_private()
    info = candidates_parallel(files, ip2as=ip2as, poolsize=args.poolsize)
    prevs = toprevs(info)
    directory = os.path.dirname(args.output)
    if directory:
        os.makedirs(directory, exist_ok=True)
    # with open(args.output, 'wb') as f:
    #     pickle.dump(prevs, f)
    with fopen(args.output, 'wt') as f:
        for k, v in prevs.items():
            p = ','.join(v)
            f.write('{}\t{}\n'.format(k, p))

if __name__ == '__main__':
    main()

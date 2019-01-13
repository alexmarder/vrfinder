#!/usr/bin/env python
import json
import subprocess
from argparse import ArgumentParser, FileType
from multiprocessing.pool import ThreadPool, Pool

from traceutils.progress.bar import Progress
from traceutils.radix.ip2as import IP2AS
from traceutils.scamper.warts import WartsReader
from traceutils.utils.net import prefix_addrs


_ip2as: IP2AS = None


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


def candidates_parallel(filenames, ip2as=None):
    global _ip2as
    if ip2as is not None:
        _ip2as = ip2as
    twos = set()
    fours = set()
    pb = Progress(len(filenames), message='Reading traceroutes', callback=lambda: 'Twos {:,d} Fours {:,d}'.format(len(twos), len(fours)))
    with Pool(2) as pool:
        for newtwos, newfours in pb.iterator(pool.imap_unordered(candidates, filenames)):
            twos.update(newtwos)
            fours.update(newfours)
    return twos, fours


def candidates_sequential(filenames, ip2as=None):
    global _ip2as
    if ip2as is not None:
        _ip2as = ip2as
    twos = set()
    fours = set()
    pb = Progress(len(filenames), message='Reading traceroutes', callback=lambda: 'Twos {:,d} Fours {:,d}'.format(len(twos), len(fours)))
    for filename in pb.iterator(filenames):
        candidates(filename, twos=twos, fours=fours)
    return twos, fours


def candidates(filename, ip2as=None, twos=None, fours=None):
    global _ip2as
    if ip2as is not None:
        _ip2as = ip2as
    if twos is None:
        twos = set()
    if fours is None:
        fours = set()
    with WartsReader(filename) as f:
        for trace in f:
            trace.prune_dups()
            trace.prune_loops()
            packed = [hop.set_packed() for hop in trace.hops]
            for i in range(len(packed) - 1):
                b1 = packed[i]
                if _ip2as.asn_packed(b1) >= 0:
                    b2 = packed[i+1]
                    if are_adjacent(b1, b2):
                        size = valid_pair(b1, b2)
                        if size != 0:
                            pair = (trace.hops[i].addr, trace.hops[i+1].addr)
                            if size == 2:
                                twos.add(pair)
                            elif size == 4:
                                fours.add(pair)
    return twos, fours


def test_candidates(addrs):
    results = {}
    pb = Progress(len(addrs), 'Pinging addrs')
    with ThreadPool(150) as pool:
        for addr, result in pb.iterator(pool.imap_unordered(ping_test, addrs)):
            results[addr] = result
    return results


def ping_test(addr):
    responses = 0
    addrs = prefix_addrs(addr, 2)
    for i in range(len(addrs)):
        addr2 = addrs[i]
        result = ping(addr2)
        if result:
            if i == 0 or i == 3:
                return addr, -1
            else:
                responses += 1
    return addr, responses


def ping(addr):
    for _ in range(3):
        cp = subprocess.run(['ping', '-q', '-c', '1', '-W', '1', addr], stdout=subprocess.DEVNULL)
        if cp.returncode == 0:
            return True
    return False


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

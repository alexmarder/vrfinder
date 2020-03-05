import os
from collections import defaultdict
from copy import deepcopy
from multiprocessing.pool import Pool
from typing import Optional

from traceutils.progress import Progress
from traceutils.radix.ip2as import IP2AS
from traceutils.scamper.hop import ICMPType
from traceutils.scamper.warts import WartsReader
from traceutils.utils.net import otherside

from candidate_info import CandidateInfo
from finder import valid_pair, are_adjacent
from finder_info import FinderInfo
from finder_prune import FinderPrune

_ip2as: Optional[IP2AS] = None

def lasttwo(filename):
    results = set()
    with WartsReader(filename) as f:
        for trace in f:
            if trace.stop_reason == 'COMPLETED':
                if len(trace.hops) >= 2:
                    x = trace.hops[-2]
                    y = trace.hops[-1]
                    if x.probe_ttl == y.probe_ttl - 1:
                        if y.type == ICMPType.echo_reply:
                            subnet = are_adjacent(x.set_packed(), y.set_packed())
                            if subnet:
                                results.add((x.addr, y.addr))
    return results

def parse_lasttwo(files):
    vpresults = {}
    allresults = set()
    pb = Progress(len(files), 'Reading last twos', callback=lambda: '{:,d}'.format(len(allresults)))
    for file in pb.iterator(files):
        vp = os.path.basename(file).partition('.')[0]
        results = lasttwo(file)
        allresults.update(results)
        vpresults[vp] = results
    return allresults, vpresults

def parse_lasttwo_parallel(files):
    vpresults = {}
    allresults = set()
    pb = Progress(len(files), 'Reading last twos', callback=lambda: '{:,d}'.format(len(allresults)))
    with Pool(25) as pool:
        for file, results in pb.iterator(zip(files, pool.imap(lasttwo, files))):
            vp = os.path.basename(file).partition('.')[0]
            allresults.update(results)
            vpresults[vp] = results
    return allresults, vpresults

def byasn(addrs, ip2as: IP2AS):
    asns = defaultdict(set)
    for addr in addrs:
        asns[ip2as[addr]].add(addr)
    return asns

import os
from multiprocessing.pool import Pool
from typing import Optional, Set, Any, Dict

from traceutils.progress.bar import Progress
from traceutils.scamper.hop import ICMPType
from traceutils.scamper.warts import WartsReader

from finder import are_adjacent, valid_pair

# dsts: Optional[Dict[str, Dict[str, Set[Any]]]] = None
class Results:
    def __init__(self):
        self.confirmed = set()

    def __repr__(self):
        return 'C {:,d}'.format(len(self.confirmed))

    def update(self, results):
        for k, v in vars(results).items():
            getattr(self, k).update(v)

class TestResults:
    def __init__(self):
        self.confirmed = set()
        self.reject = set()
        self.missing = set()

    def __repr__(self):
        return 'C {:,d} R {:,d} M {:,d}'.format(len(self.confirmed), len(self.reject), len(self.missing))

def dst_candidates(filename: str, ip2as=None, info: Results = None):
    global _ip2as
    if ip2as is not None:
        _ip2as = ip2as
    if info is None:
        info = Results()
    vp = os.path.basename(filename).partition('.')[0]
    with WartsReader(filename) as f:
        for trace in f:
            if not trace.hops: continue
            trace.prune_private(_ip2as)
            if not trace.hops: continue
            trace.prune_loops(keepfirst=True)
            if not trace.hops: continue
            packed = [hop.set_packed() for hop in trace.hops]
            for i in range(len(packed) - 1):
                b1 = packed[i]
                b2 = packed[i+1]
                if b1 == b2:
                    continue
                x = trace.hops[i]
                y = trace.hops[i+1]
                if x.probe_ttl == y.probe_ttl - 1:
                    if x.type == ICMPType.time_exceeded and (y.addr != trace.dst or y.type == ICMPType.time_exceeded or y.type == ICMPType.echo_reply):
                        xasn = _ip2as.asn_packed(b1)
                        if xasn >= 0:
                            if are_adjacent(b1, b2):
                                size = valid_pair(b1, b2)
                                if size == 2 or size == 4 or size == -2 or size == -4:
                                    info.confirmed.add((vp, trace.dst, x.addr))
                                    continue
    return info

def parse_dsts_parallel(files, ip2as):
    global _ip2as
    _ip2as = ip2as
    allresults = Results()
    pb = Progress(len(files), 'Reading last twos', callback=allresults.__repr__)
    with Pool(25) as pool:
        for results in pb.iterator(pool.imap_unordered(dst_candidates, files)):
            allresults.update(results)
    return allresults

def testdsts(res: Results, vpdests):
    info = TestResults()
    vps = set()
    for vp, dst, x in res.confirmed:
        vps.add(vp)
        dests = vpdests.get(vp)
        if x in dests[dst]:
            info.confirmed.add(x)
    for vp, dests in vpdests.items():
        if vp in vps:
            for xs in dests.values():
                rej = xs - info.confirmed
                info.reject.update(rej)
        else:
            for xs in dests.values():
                info.missing.update(xs)
    info.reject -= info.confirmed
    info.missing -= info.confirmed | info.reject
    return info

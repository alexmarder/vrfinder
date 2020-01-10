import os
from collections import defaultdict

from traceutils.progress import Progress
from traceutils.scamper.hop import ICMPType
from traceutils.scamper.warts import WartsReader
from traceutils.utils.net import otherside

from candidate_info import CandidateInfo
from finder import valid_pair, are_adjacent

class Results:
    def __init__(self):
        self.confirmed = set()
        self.reject = set()
        self.unknown = set()

    def __repr__(self):
        return 'C {:,d} R {:,d} U {:,d}'.format(len(self.confirmed), len(self.reject), len(self.unknown))

    def subtract(self):
        self.reject -= self.confirmed
        self.unknown -= self.confirmed
        self.unknown -= self.reject

class CandResults(Results):
    def __init__(self):
        super().__init__()
        self.rejpaths = {}

class TraceResult(Results):
    def __init__(self):
        super().__init__()
        self.rejpaths = set()

    def match_candidates(self, info: CandidateInfo):
        rejpaths = defaultdict(set)
        for y, path in self.rejpaths:
            rejpaths[y].add(path)
        res = CandResults()
        pairs = info.pairs()
        for x, y in pairs:
            if y in self.confirmed:
                res.confirmed.add(x)
            elif y in self.reject:
                res.reject.add(x)
                res.rejpaths[x] = rejpaths[y]
            elif y in self.unknown:
                res.unknown.add(x)
        return res

    def update(self, results):
        for key, value in vars(self).items():
            value.update(getattr(results, key))

def lasttwo(filename, ip2as):
    results = TraceResult()
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
                                results.confirmed.add(y.addr)
                            else:
                                asns = [ip2as[h.addr] for h in trace.hops]
                                results.rejpaths.add((y.addr, tuple(asns)))
                                results.reject.add(y.addr)
                            continue
            results.unknown.add(trace.dst)
    return results

def parse_lasttwo(files, ip2as):
    vpresults = {}
    allresults = TraceResult()
    pb = Progress(len(files), 'Reading last twos', callback=allresults.__repr__)
    for file in pb.iterator(files):
        vp = os.path.basename(file).partition('.')[0]
        results = lasttwo(file, ip2as)
        allresults.update(results)
        vpresults[vp] = results
    return allresults, vpresults

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

class Results:
    def __init__(self):
        self.confirmed = set()
        self.reject = set()
        self.unknown = set()

    def __len__(self):
        return len(self.confirmed | self.reject | self.unknown)

    def __repr__(self):
        return 'C {:,d} R {:,d} U {:,d}'.format(len(self.confirmed), len(self.reject), len(self.unknown))

    @classmethod
    def duplicate(cls, res):
        newres = cls()
        for k in vars(res):
            try:
                setattr(newres, k, deepcopy(getattr(res, k)))
            except TypeError:
                print(k)
                raise
        return newres

    def subtract(self):
        self.reject -= self.confirmed
        self.unknown -= self.confirmed
        self.unknown -= self.reject

class CandResults(Results):
    def __init__(self):
        super().__init__()
        self.rejpaths = {}
        self.unknown2 = set()
        self.missing = set()

    def __len__(self):
        return len(self.confirmed | self.reject | self.unknown | self.unknown2 | self.missing)

    def __repr__(self):
        return super().__repr__() + ' U2 {:,d} M {:,d}'.format(len(self.unknown2), len(self.missing))

    def byasn(self, ip2as: IP2AS):
        conf = byasn(self.confirmed, ip2as)
        rej = byasn(self.reject, ip2as)
        unk = byasn(self.missing | self.unknown | self.unknown2, ip2as)
        return conf, rej, unk

    def fix_rejects(self, ip2as: IP2AS, info: CandidateInfo):
        keep = set()
        prev = info.tripprev()
        for x, paths in self.rejpaths.items():
            asns = {ip2as[addr] for addr in prev[x]}
            for path in paths:
                if set(path) & asns:
                    keep.add(x)
        self.unknown2 = self.reject - keep
        self.reject = keep

    def update_echos(self, echo_cfas):
        self.confirmed.update(echo_cfas)
        self.unknown -= echo_cfas
        self.unknown2 -= echo_cfas
        self.missing -= echo_cfas

    def limit(self, info: FinderPrune, duplicate=False):
        if duplicate:
            res = self.duplicate(self)
            res.limit(info, duplicate=False)
            return res
        cfas = info.twos().keys() | info.fours().keys()
        self.confirmed &= cfas
        self.reject &= cfas
        self.unknown &= cfas
        self.unknown2 &= cfas
        self.missing &= cfas

    def fracs(self):
        total = len(self.confirmed | self.reject | self.unknown | self.unknown2)
        conf = len(self.confirmed) / total
        rej = len(self.reject - self.confirmed) / total
        unk = len((self.unknown | self.unknown2) - self.confirmed - self.reject) / total
        return {'conf': conf, 'rej': rej, 'unk': unk, 'total': total}

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
            else:
                res.missing.add(x)
        return res

    def update(self, results):
        for key, value in vars(self).items():
            value.update(getattr(results, key))

def lasttwo(filename, ip2as=None):
    if ip2as is None:
        ip2as = _ip2as
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

def parse_lasttwo_parallel(files, ip2as):
    global _ip2as
    _ip2as = ip2as
    allresults = TraceResult()
    pb = Progress(len(files), 'Reading last twos', callback=allresults.__repr__)
    with Pool(25) as pool:
        for results in pb.iterator(pool.imap_unordered(lasttwo, files)):
            allresults.update(results)
    return allresults

def byasn(addrs, ip2as: IP2AS):
    asns = defaultdict(set)
    for addr in addrs:
        asns[ip2as[addr]].add(addr)
    return asns

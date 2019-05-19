import pickle
from collections import defaultdict

from traceutils.as2org.as2org import AS2Org
from traceutils.ixps.ixps import PeeringDB
from traceutils.progress.bar import Progress
from traceutils.utils.net import otherside


class CandidateInfo:

    def __init__(self):
        self.twos = set()
        self.fours = set()
        self.ixps = set()
        self.cycles = set()
        self.nexthop = set()
        self.multi = set()
        self.echos = set()
        self.last = set()
        self.nextecho = set()
        self.multiecho = set()
        self.tuples = set()
        self.triplets = set()

    def __repr__(self):
        return '2 {:,d} 4 {:,d} X {:,d} C {:,d} N {:,d} M {:,d} E {:,d} L {:,d} NE {:,d} ME {:,d} T {:,d} 3 {:,d}'.format(len(self.twos), len(self.fours), len(self.ixps), len(self.cycles), len(self.nexthop), len(self.multi), len(self.echos), len(self.last), len(self.nextecho), len(self.multiecho), len(self.tuples), len(self.triplets))

    def alladdrs(self):
        return self.middle_echo() | self.echos | self.last

    def dump(self, filename, prune=True):
        if prune:
            self.prune()
        d = self.__dict__
        with open(filename, 'wb') as f:
            pickle.dump(d, f)

    def ixpaddrs(self):
        return {x for _, x, y in self.ixps if x != y}

    def ixpprune(self, peeringdb: PeeringDB, as2org: AS2Org):
        ixps = set()
        pasns = self.ixpprev()
        for x, asns in pasns.items():
            if x in peeringdb.addrs:
                asn = peeringdb.addrs[x]
                org = as2org[asn]
                orgs = {as2org[asn] for asn in asns if asn is not None}
                if org in orgs:
                    ixps.add(x)
            else:
                pass
                # ixps.add(x)
        return ixps

    def ixpprev(self):
        pasns = defaultdict(set)
        for pasn, x, _ in self.ixps:
            pasns[x].add(pasn)
        return dict(pasns)

    def lastecho(self):
        return self.last | self.nextecho | self.multiecho

    @classmethod
    def load(cls, filename):
        info = cls()
        with open(filename, 'rb') as f:
            d = pickle.load(f)
        if not isinstance(d, dict):
            d = d.__dict__
        # print(d.keys())
        for k, v in d.items():
            if hasattr(info, k):
                info.__getattribute__(k).update(v)
        return info

    def middle(self):
        return self.nexthop | self.multi

    def middle_echo(self):
        return self.middle() | self.nextecho | self.multiecho

    def noecho(self):
        return self.middle_echo() | self.last

    def succ(self):
        succ = defaultdict(set)
        pb = Progress(len(self.tuples), '', increment=500000)
        for x, y in pb.iterator(self.tuples):
            succ[x].add(y)
        return dict(succ)

    def prev(self):
        prev = defaultdict(set)
        pb = Progress(len(self.tuples), '', increment=500000)
        for x, y in pb.iterator(self.tuples):
            prev[y].add(x)
        return dict(prev)

    def trippairs(self):
        pairs = defaultdict(list)
        for w, x, y in self.triplets:
            pairs[x].append((w, y))
        return dict(pairs)

    def tripaddrs(self):
        return {a for trip in self.triplets for a in trip}

    def prune(self):
        self.nextecho -= self.nexthop
        self.multi -= self.nexthop
        self.multiecho -= self.multi
        self.last -= self.nexthop
        self.last -= self.multi
        self.echos -= self.nexthop
        self.echos -= self.multi
        self.echos -= self.last

    def cycle_candidates(self):
        cfas = set()
        for cycle in self.cycles:
            for x, y in zip(cycle, cycle[1:]):
                try:
                    if y == otherside(x, 2) or y == otherside(x, 4):
                        cfas.add(x)
                except:
                    pass
        return cfas

    def row(self, name=None):
        middle = self.middle_echo()
        twos = len(self.twos)
        fours = len(self.fours)
        ixps = len(self.ixpaddrs())
        total = twos + fours + ixps
        allcandidates = self.twos | self.fours | self.ixpaddrs()
        cycle_candidates = self.cycle_candidates()
        cycle_cfas = len(cycle_candidates - allcandidates)
        cycles = len(self.cycles)
        d = {'twos': twos, 'fours': fours, 'ixps': ixps, 'total': total, 'totalp': total / len(middle), 'cycles': cycle_cfas, 'cycle_frac': cycle_cfas / cycles}
        if name is not None:
            d['name'] = name
        return d

    def update(self, info):
        self.twos.update(info.twos)
        self.fours.update(info.fours)
        self.ixps.update(info.ixps)
        self.cycles.update(info.cycles)
        self.nexthop.update(info.nexthop)
        self.multi.update(info.multi)
        self.echos.update(info.echos)
        self.last.update(info.last)
        self.nextecho.update(info.nextecho)
        self.multiecho.update(info.multiecho)
        self.tuples.update(info.tuples)
        self.triplets.update(info.triplets)


class LastInfo:

    def __init__(self, filename, candidates: CandidateInfo):
        self.filename = filename
        self.candidates = candidates
        with open(filename, 'rb') as f:
            d = pickle.load(f)
        self.newtwos = d['twos']
        self.newfours = d['fours']
        self.twos = candidates.twos | self.newtwos
        self.fours = candidates.fours | self.newfours

    def __getattr__(self, name):
        return getattr(self.candidates, name)

    def __repr__(self):
        return 'Twos {:,d} Fours {:,d}'.format(len(self.twos), len(self.fours))

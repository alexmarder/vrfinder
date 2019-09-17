import os
import pickle
from collections import defaultdict
from copy import copy, deepcopy

from traceutils.as2org.as2org import AS2Org
from traceutils.file2.file2 import File2
from traceutils.ixps.ixps import PeeringDB
from traceutils.progress.bar import Progress
from traceutils.utils.net import otherside as otherside_err, prefix_addrs

from alias import Alias


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
        self.unreach = set()
        self.nounreach = set()
        self.spoofing = set()
        self.original_fours = None
        self.rttls = set()
        self.echofours = set()
        self.echotwos = set()

    @classmethod
    def duplicate(cls, info):
        newinfo = cls()
        dps = ['twos', 'fours', 'ixps']
        # for k in dps:
        #     setattr(newinfo, k, deepcopy(getattr(info, k)))
        for k, v in vars(info).items():
            if k in dps:
                setattr(newinfo, k, deepcopy(getattr(info, k)))
            else:
                setattr(newinfo, k, getattr(info, k))
        return newinfo

    def __repr__(self):
        return '2 {:,d} 4 {:,d} X {:,d} C {:,d} N {:,d} M {:,d} E {:,d} L {:,d} NE {:,d} ME {:,d} 3 {:,d} U {:,d} NU {:,d} S {:,d} R {:,d} E2 {:,d} E4 {:,d}'.format(len(self.twos), len(self.fours), len(self.ixps), len(self.cycles), len(self.nexthop), len(self.multi), len(self.echos), len(self.last), len(self.nextecho), len(self.multiecho), len(self.triplets), len(self.unreach), len(self.nounreach), len(self.spoofing), len(self.rttls), len(self.echotwos), len(self.echofours))

    def alladdrs(self):
        return self.middle_echo() | self.echos | self.last | self.cyaddrs()

    @property
    def cfas(self):
        return self.twos | self.fours | self.ixpaddrs()

    def cyaddrs(self):
        return {x for cycle in self.cycles for x in cycle}

    def dump(self, filename, prune=True):
        if prune:
            self.prune()
        d = self.__dict__
        with open(filename, 'wb') as f:
            pickle.dump(d, f)

    def fixfours(self):
        self.original_fours = self.fours
        self.fours = self.fours - self.twos

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

    def lastaddrs(self):
        return self.last - (self.middle_echo())

    def lastecho(self):
        return (self.last | self.nextecho | self.multiecho) - self.middle()

    @classmethod
    def load(cls, filename):
        info = cls()
        with open(filename, 'rb') as f:
            d = pickle.load(f)
        if not isinstance(d, dict):
            d = d.__dict__
        # print(d.keys())
        for k, v in d.items():
            if k != 'original_fours' and hasattr(info, k):
                info.__getattribute__(k).update(v)
        return info

    def middle(self):
        return self.nexthop | self.multi

    def middle_echo(self):
        return self.middle() | self.nextecho | self.multiecho

    def noecho(self):
        return self.middle_echo() | self.last

    def prune_router_loops(self, alias: Alias):
        ixps = defaultdict(list)
        for asn, x, y in self.ixps:
            ixps[x, y].append((asn, x, y))
        for x, y, z in self.triplets:
            if x in alias.aliases(z):
                if z == otherside(y, 4):
                    self.fours.discard(y)
                elif z == otherside(y, 2):
                    self.twos.discard(y)
                elif y in self.ixps:
                    found = ixps[y, z]
                    for t in found:
                        self.ixps.discard(t)

    def succ(self):
        succ = defaultdict(set)
        pb = Progress(len(self.tuples), '', increment=500000)
        for x, y in pb.iterator(self.tuples):
            succ[x].add(y)
        return dict(succ)

    def pairs(self):
        pairs = {(x, otherside(x, 2)) for x in self.twos}
        pairs.update({(x, otherside(x, 4)) for x in self.fours})
        return pairs

    def prev(self, filename=None, tuples=None):
        if tuples is None:
            if filename is not None:
                with open(filename, 'rb') as f:
                    tuples = pickle.load(f)['tuples']
            else:
                tuples = self.tuples
        prev = defaultdict(set)
        pb = Progress(len(tuples), '', increment=500000)
        for x, y in pb.iterator(tuples):
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
                if y == otherside(x, 2) or y == otherside(x, 4):
                    cfas.add(x)
        return cfas

    def remove_spoofing(self):
        unreach_only = self.unreach_only()
        self.fours -= unreach_only
        self.twos -= unreach_only

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

    def ttl_dict(self):
        d = defaultdict(set)
        for x, y, xrttl, yrttl in self.rttls:
            d[x, y].add((xrttl, yrttl))
        d.default_factory = None
        return d

    def unreach_only(self):
        return self.spoofing - self.nounreach

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
        self.unreach.update(info.unreach)
        self.nounreach.update(info.nounreach)
        self.spoofing.update(info.spoofing)
        self.rttls.update(info.rttls)

    def write_fours(self, filename):
        addrs = {a for four in self.fours for a in prefix_addrs(four, 2)}
        write_addrs(filename, addrs)

    def write_lasts(self, filename):
        addrs = self.noecho()
        write_addrs(filename, addrs)


class LastInfo:

    def __init__(self, candidates: CandidateInfo):
        self.candidates = candidates
        self.filename = None
        self.newtwos = None
        self.newfours = None
        self.twos = None
        self.fours = None
        self.original_newfours = None

    @classmethod
    def duplicate(cls, oldinfo, candidates: CandidateInfo = None):
        if candidates is None:
            candidates = CandidateInfo.duplicate(oldinfo.candidates)
        info = cls(candidates)
        for k, v in vars(info).items():
            setattr(info, k, deepcopy(getattr(oldinfo, k)))
        return info

    @classmethod
    def from_file(cls, filename, candidates: CandidateInfo):
        info = cls(candidates)
        info.filename = filename
        with open(filename, 'rb') as f:
            d = pickle.load(f)
        twos = d['twos'] - candidates.middle()
        fours = d['fours'] - candidates.middle()
        info.newtwos = twos
        info.newfours = fours
        info.twos = candidates.twos | info.newtwos
        info.fours = (candidates.fours | info.newfours) - info.twos
        info.original_newfours = None

    @property
    def newcfas(self):
        return (self.twos | self.fours) - (self.candidates.twos | self.candidates.fours)

    def __getattr__(self, name):
        return getattr(self.candidates, name)

    def __repr__(self):
        return 'Twos {:,d} Fours {:,d}'.format(len(self.twos), len(self.fours))


def write_addrs(filename, addrs):
    directory = os.path.dirname(filename)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with File2(filename, 'wt') as f:
        f.writelines('{}\n'.format(a) for a in addrs)


def otherside(addr, n):
    try:
        return otherside_err(addr, n)
    except:
        return None

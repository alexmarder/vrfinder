import os
import pickle
from collections import defaultdict
from copy import copy, deepcopy
from typing import Union, Set, Any, NewType, DefaultDict, Tuple, Dict
import pandas as pd

from traceutils.as2org.as2org import AS2Org
from traceutils.file2.file2 import File2
from traceutils.ixps.ixps import PeeringDB
from traceutils.progress.bar import Progress
from traceutils.utils.net import otherside as otherside_err, prefix_addrs

from alias import Alias


IXPManagerT = NewType('IXPManager', DefaultDict[str, Set[Tuple[int, str, str]]])


class IXPManager(defaultdict):
    def __init__(self, *args, **kwargs):
        super().__init__(set, *args, **kwargs)

    def copy(self):
        return IXPManager({k: set(v) for k, v in self.items()})

    @classmethod
    def from_tuples(cls, tuples):
        ixps = cls()
        for asn, x, y in tuples:
            if x != y:
                ixps[x].add((asn, x, y))
        ixps.default_factory = None
        return ixps

    def ixps(self):
        for k, v in self.items():
            if v:
                yield k

    def remove(self, asn, x, y):
        if x in self:
            tuples = self[x]
            t = (asn, x, y)
            if t in tuples:
                tuples.discard(t)
                if not tuples:
                    del self[x]


class CandidateInfo:

    def __init__(self):
        self.twos = set()
        self.fours = set()
        self.ixps: Union[Set[Any], IXPManagerT] = set()
        self.ixp_tuples = set()
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
        self.dsts = set()
        self.dst_asns = set()

    @classmethod
    def duplicate(cls, info):
        newinfo = cls()
        dps = ['twos', 'fours']
        for k, v in vars(info).items():
            if k == 'ixps':
                newinfo.ixps = info.ixps.copy()
            elif k in dps:
                try:
                    setattr(newinfo, k, deepcopy(getattr(info, k)))
                except TypeError:
                    print(k)
                    raise
            else:
                setattr(newinfo, k, getattr(info, k))
        return newinfo

    def __repr__(self):
        return '2 {:,d} 4 {:,d} X {:,d}'.format(len(self.twos), len(self.fours), len(self.ixps))

    def __str__(self):
        return '2 {:,d} 4 {:,d} X {:,d} C {:,d} N {:,d} M {:,d} E {:,d} L {:,d} NE {:,d} ME {:,d} 3 {:,d} U {:,d} NU {:,d} S {:,d} R {:,d} E2 {:,d} E4 {:,d} D {:,d}'.format(len(self.twos), len(self.fours), len(self.ixps), len(self.cycles), len(self.nexthop), len(self.multi), len(self.echos), len(self.last), len(self.nextecho), len(self.multiecho), len(self.triplets), len(self.unreach), len(self.nounreach), len(self.spoofing), len(self.rttls), len(self.echotwos), len(self.echofours), len(self.dst_asns))

    def add_lasts(self, filename):
        with open(filename, 'rb') as f:
            d = pickle.load(f)
        self.twos.update(d['twos'])
        self.fours.update(d['fours'])

    def alladdrs(self):
        return self.middle_echo() | self.echos | self.last | self.cyaddrs()

    @property
    def cfas(self):
        return self.twos | self.fours | set(self.ixps.ixps())

    def create_ixps(self, tuples):
        self.ixp_tuples = tuples
        self.ixps = IXPManager.from_tuples(tuples)

    def cyaddrs(self):
        return {x for cycle in self.cycles for x in cycle}

    def cyaddrs1(self):
        return {cycle[0] for cycle in self.cycles}

    def destpairs(self, increment=100000):
        dps = defaultdict(set)
        pb = Progress(len(self.dst_asns), 'Creating destpairs', increment=increment)
        for x, dasn in pb.iterator(self.dst_asns):
            dps[x.addr].add(dasn)
        dps.default_factory = None
        return dps

    def dump(self, filename, prune=True):
        if prune:
            self.prune()
        d = self.__dict__
        with open(filename, 'wb') as f:
            pickle.dump(d, f)

    def fixfours(self):
        self.original_fours = self.fours
        self.fours = self.fours - self.twos

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
        info.create_ixps(info.ixps)
        return info

    @classmethod
    def loads(cls, d):
        info = cls()
        for k, v in d.items():
            if k != 'original_fours' and hasattr(info, k):
                info.__getattribute__(k).update(v)
        info.create_ixps(info.ixps)
        return info

    def middle(self):
        return self.nexthop | self.multi

    def middle_echo(self):
        return self.middle() | self.nextecho | self.multiecho

    def noecho(self):
        return self.middle_echo() | self.last

    def status(self):
        return repr(self)

    # def row(self, index):
    #     return pd.Series(dict(twos=len(self.twos), fours=len(self.fours), ixps=len(self.ixps)), name=index)
    #     # return dict(twos=len(self.twos), fours=len(self.fours), ixps=len(self.ixps)

    def prune_spoof_fix(self):
        info = CandidateInfo.duplicate(self)
        info.prune_spoofing()
        info.fixfours()
        return info

    def prune_all(self, valid: Dict[str, int], peeringdb: PeeringDB=None, as2org: AS2Org=None, alias: Alias=None, verbose=False, percent=False):
        middle = self.middle_echo() if percent else None
        rows = []
        if verbose:
            rows.append(self.row('Initial', percent=percent, middle=middle))
        self.prune_spoofing()
        if verbose:
            rows.append(self.row('Spoofing', percent=percent, middle=middle))
        self.fixfours()
        if verbose:
            rows.append(self.row('Fix Fours', percent=percent, middle=middle))
        self.prune_ixps(peeringdb, as2org)
        if verbose:
            rows.append(self.row('IXPs', percent=percent, middle=middle))
        self.prune_pingtest(valid)
        if verbose:
            rows.append(self.row('Ping Test', percent=percent, middle=middle))
        self.prune_router_loops(alias)
        if verbose:
            rows.append(self.row('Router Loops', percent=percent, middle=middle))
        if verbose:
            df = pd.DataFrame(rows)
            if percent:
                df['totalp'] = df.totalp.round(1)
            return df

    def prune_ixps(self, peeringdb: PeeringDB, as2org: AS2Org):
        prune = set()
        for x, tuples in self.ixps.items():
            if x in peeringdb.addrs:
                asn = peeringdb.addrs[x]
                org = as2org[asn]
                orgs = {as2org[asn] for asn, _, _ in tuples if asn is not None}
                if org not in orgs:
                    prune.add(x)
            else:
                prune.add(x)
        for x in prune:
            del self.ixps[x]

    def prune_pingtest(self, valid: Dict[str, int]):
        prune = {addr for addr in self.fours if valid.get(addr, 2) <= 1}
        self.fours -= prune

    def prune_spoofing(self):
        unreach_only = self.unreach_only()
        self.fours -= unreach_only
        self.twos -= unreach_only

    def prune_router_loops(self, alias: Alias, duplicate=False):
        if duplicate:
            info = CandidateInfo.duplicate(self)
            info.prune_router_loops(alias, duplicate=False)
            return info
        ixps = defaultdict(list)
        for asn, x, y in self.ixp_tuples:
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
                        self.ixps.remove(*t)

    def succ(self, filename=None, tuples=None):
        if tuples is None:
            if filename is not None:
                with open(filename, 'rb') as f:
                    tuples = pickle.load(f)['tuples']
            else:
                tuples = self.tuples
        succ = defaultdict(set)
        pb = Progress(len(tuples), '', increment=500000)
        for x, y in pb.iterator(tuples):
            succ[x].add(y)
        succ.default_factory = None
        return succ

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

    def row(self, name=None, percent=False, middle=None, decimal=1, extras=False):
        # ixpset = set(self.ixps.ixps())
        twos = len(self.twos)
        fours = len(self.fours)
        ixps = len(self.ixps)
        total = twos + fours + ixps
        # cycle_candidates = self.cycle_candidates()
        # cycle_cfas = len(cycle_candidates - allcandidates)
        # cycles = len(self.cycles)
        d = {'twos': twos, 'fours': fours, 'ixps': ixps, 'total': total}
        if percent:
            if middle is None:
                middle = self.middle_echo()
            allcandidates = self.twos | self.fours | self.ixps.keys()
            middlecand = allcandidates & middle
            d['totalp'] = 100 * len(middlecand) / len(middle)
            if extras:
                d['twosp'] = 100 * len(self.twos & middle) / len(middle)
                d['foursp'] = 100 * len(self.fours & middle) / len(middle)
                d['cyp'] = 100 * len(self.cycle_candidates()) / len(middle)
                d['middle'] = len(middle)
        return pd.Series(d, name=name)

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
        self.echofours.update(info.echofours)
        self.echotwos.update(info.echotwos)
        self.dsts.update(info.dsts)
        self.dst_asns.update(info.dst_asns)

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

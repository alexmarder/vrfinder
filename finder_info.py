import os
import pickle
from collections import defaultdict, Counter
from copy import deepcopy
from typing import Set

from traceutils.file2.file2 import File2
from traceutils.utils.net import otherside as otherside_err


class FinderInfo:

    def __init__(self):
        self.twos = Counter()
        self.fours = Counter()
        self.ixps = set()
        self.ixp_adjs = Counter()
        self.ixp_tuples = set()
        self.middle = Counter()
        self.last = Counter()
        self.tuples = set()
        self.triplets = set()
        self.nounreach: Set[str] = set()
        self.spoofing: Set[str] = set()
        self.rttls = Counter()
        self.echofours = Counter()
        self.echotwos = Counter()
        self.middlefours = Counter()
        self.middletwos = Counter()
        self.lastfours = Counter()
        self.lasttwos = Counter()
        self.dsts = set()
        self.dst_asns = set()
        self.loops = Counter()

    def __repr__(self):
        return '2 {:,d} 4 {:,d} X {:,d}'.format(len(self.twos), len(self.fours), len(self.ixps))

    def __str__(self):
        return '2 {:,d} 4 {:,d} X {:,d} C {:,d} N {:,d} M {:,d} E {:,d} L {:,d} NE {:,d} ME {:,d} 3 {:,d} U {:,d} NU {:,d} S {:,d} R {:,d} E2 {:,d} E4 {:,d} D {:,d}'.format(len(self.twos), len(self.fours), len(self.ixps), len(self.cycles), len(self.nexthop), len(self.multi), len(self.echos), len(self.last), len(self.nextecho), len(self.multiecho), len(self.triplets), len(self.unreach), len(self.nounreach), len(self.spoofing), len(self.rttls), len(self.echotwos), len(self.echofours), len(self.dst_asns))

    def dump(self, filename):
        d = self.dumps()
        with open(filename, 'wb') as f:
            pickle.dump(d, f)

    def dumps(self):
        return vars(self)

    @classmethod
    def duplicate(cls, info):
        newinfo = cls()
        dps = ['twos', 'fours', 'ixps']
        for k, v in vars(info).items():
            if k in dps:
                try:
                    setattr(newinfo, k, deepcopy(getattr(info, k)))
                except TypeError:
                    print(k)
                    raise
            else:
                setattr(newinfo, k, getattr(info, k))
        return newinfo

    @classmethod
    def load(cls, filename):
        info = cls()
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
        # info.create_ixps(info.ixps)
        return info

    def update(self, info):
        for k, v in vars(info).items():
            getattr(self, k).update(v)

class FinderInfoContainer(defaultdict):
    @classmethod
    def default(cls):
        return cls(FinderInfo)

    def dump(self, filename, prune=True):
        d = {vp: info.dumps(prune=prune) for vp, info in self.items()}
        with open(filename, 'wb') as f:
            pickle.dump(d, f)

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

def adjust_rttl(rttl):
    if rttl > 128:
        return 255 - rttl
    if rttl > 65:
        return 128 - rttl
    return 65 - rttl

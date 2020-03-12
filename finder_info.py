import os
import pickle
from collections import defaultdict, Counter
from copy import deepcopy
from typing import Set

from traceutils.file2.file2 import File2
from traceutils.utils.net import otherside as otherside_err


class FinderInfo:

    def __init__(self):
        self.ixps = set()
        self.ixp_adjs = Counter()
        self.ixp_tuples = set()
        self.middle = Counter()
        self.last = Counter()
        self.lastechos = Counter()
        self.tuples = set()
        self.triplets = set()
        self.nounreach: Set[str] = set()
        self.spoofing: Set[str] = set()
        self.rttls = Counter()
        self.ipids = Counter()
        self.echofours = Counter()
        self.echotwos = Counter()
        self.middlefours = Counter()
        self.middletwos = Counter()
        self.lastfours = Counter()
        self.lasttwos = Counter()
        self.dsts = set()
        self.dst_asns = set()
        # self.loops = Counter()
        self.looptwos = Counter()
        self.loopfours = Counter()
        self.loopother = Counter()

    def __repr__(self):
        return 'M2 {m2:,d} M4 {m4:,d} L2 {l2:,d} L4 {l4:,d} E2 {e2:,d} E4 {e4:,d} X {ixps:,d} C2 {c2:,d} C4 {c4:,d}'.format(
            m2=len(self.middletwos), m4=len(self.middlefours), l2=len(self.lasttwos), l4=len(self.lastfours),
            e2=len(self.echotwos), e4=len(self.echofours), ixps=len(self.ixps), c2=len(self.looptwos),
            c4=len(self.loopfours)
        )

    def __str__(self):
        s = repr(self)
        return '{repr} L {last:,d}'.format(
            repr=s, middle=len(self.middle), last=len(self.last)
        )

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
        return info

    def update(self, info):
        for k, v in vars(info).items():
            getattr(self, k).update(v)

class FinderInfoContainer(defaultdict):
    @classmethod
    def default(cls):
        return cls(FinderInfo)

    def dump(self, filename):
        d = {vp: info.dumps() for vp, info in self.items()}
        with open(filename, 'wb') as f:
            pickle.dump(d, f)
    @staticmethod
    def load(filename):
        with open(filename, 'rb') as f:
            infos = pickle.load(f)
        infos = {k: FinderInfo.loads(v) for k, v in infos.items()}
        return infos

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

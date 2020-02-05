import pickle
from collections import defaultdict, Counter
from copy import deepcopy
from typing import Set, Dict

from traceutils.utils.net import otherside

from finder_info import FinderInfo


class FinderPrune(FinderInfo):

    def __init__(self):
        super().__init__()

    @classmethod
    def duplicate(cls, info):
        newinfo = cls()
        dps = ['middletwos', 'middlefours', 'lasttwos', 'lastfours', 'echotwos', 'echofours']
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

    def fixfours(self, duplicate=False):
        if duplicate:
            info = self.duplicate(self)
            info.fixfours(duplicate=False)
            return info
        fours = self.fours()
        twos = self.twos()
        prune = fours.keys() & twos.keys()
        for k in prune:
            if k in self.middlefours:
                self.middlefours.pop(k)
            if k in self.echofours:
                self.echofours.pop(k)
            if k in self.lastfours:
                self.lastfours.pop(k)

    def fours(self):
        return self.middlefours + self.lastfours + self.echofours

    def twos(self):
        return self.middletwos + self.lasttwos + self.echotwos

    def middle_cfas(self):
        return self.middlefours + self.middletwos

    def pairs(self, middle=True, echo=True, last=True, num=False):
        # pairs = Counter()
        if middle:
            # pairs += self.middlefours
            # pairs += self.middletwos
            yield from create_pairs(self.middlefours, 4, num=num)
            yield from create_pairs(self.middletwos, 2, num=num)
        if echo:
            # pairs += self.echofours
            # pairs += self.echotwos
            yield from create_pairs(self.echofours, 4, num=num)
            yield from create_pairs(self.echotwos, 2, num=num)
        if last:
            # pairs += self.lastfours
            # pairs += self.lasttwos
            yield from create_pairs(self.lastfours, 4, num=num)
            yield from create_pairs(self.lasttwos, 2, num=num)

    def prune_pingtest(self, valid: Dict[str, int], duplicate=False):
        if duplicate:
            info = self.duplicate(self)
            info.prune_pingtest(valid, duplicate=False)
            return info
        prune = {addr for addr in self.fours() if valid.get(addr, 2) <= 1}
        for k in prune:
            if k in self.middlefours:
                self.middlefours.pop(k)
            if k in self.echofours:
                self.echofours.pop(k)
            if k in self.lastfours:
                self.lastfours.pop(k)

    def prune_spoofing(self, duplicate=False):
        if duplicate:
            info = self.duplicate(self)
            info.prune_spoofing(duplicate=False)
            return info
        spoofing: Set[str] = self.spoofing - self.nounreach
        for k in spoofing:
            self.lastfours.pop(k, None)
            self.lasttwos.pop(k, None)

    def tripprev(self):
        prev = defaultdict(set)
        for w, x, y in self.triplets:
            prev[x].add(w)
        return prev

class FinderPruneContainer(defaultdict):
    @classmethod
    def default(cls):
        return cls(FinderPrune)

    def dump(self, filename):
        d = {vp: info.dumps() for vp, info in self.items()}
        with open(filename, 'wb') as f:
            pickle.dump(d, f)
    @staticmethod
    def load(filename):
        with open(filename, 'rb') as f:
            infos = pickle.load(f)
        infos = {k: FinderPrune.loads(v) for k, v in infos.items()}
        return infos

def create_pairs(cands, subnet, num=False):
    for x in cands:
        y = otherside(x, subnet)
        if num:
            yield x, y, cands[x]
        else:
            yield x, y

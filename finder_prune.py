import os
import pickle
from collections import defaultdict
from copy import deepcopy
from typing import Set, Dict

from traceutils.utils.net import otherside as otherside_err, prefix_addrs

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

    def last_cfas(self):
        return self.lastfours + self.lasttwos

    def echo_cfas(self):
        return self.echofours + self.echotwos

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

    def ping_output(self, file, skip=None):
        toping = {a for addr in self.fours() for a in prefix_addrs(addr, 2)}
        print('To ping: {:,d}'.format(len(toping)))
        if skip:
            toping -= skip
            print('After removing skips: {:,d}'.format(len(toping)))
        with open(file, 'w') as f:
            f.writelines('{}\n'.format(addr) for addr in toping)

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

    def prune_router_loops(self, aliases, duplicate=False):
        if duplicate:
            info = self.duplicate(self)
            info.prune_router_loops(aliases, duplicate=False)
            return info
        for x, y, z in self.triplets:
            if aliases.nids.get(x, -1) == aliases.nids.get(y, -2):
                if z == otherside(y, 4):
                    if y in self.middlefours:
                        self.middlefours.pop(y)
                    if y in self.echofours:
                        self.echofours.pop(y)
                    if y in self.lastfours:
                        self.lastfours.pop(y)
                elif z == otherside(y, 2):
                    if y in self.middletwos:
                        self.middletwos.pop(y)
                    if y in self.echotwos:
                        self.echotwos.pop(y)
                    if y in self.lasttwos:
                        self.lasttwos.pop(y)

    def prune_spoofing(self, duplicate=False):
        if duplicate:
            info = self.duplicate(self)
            info.prune_spoofing(duplicate=False)
            return info
        spoofing: Set[str] = self.spoofing - self.nounreach
        for k in spoofing:
            self.lastfours.pop(k, None)
            self.lasttwos.pop(k, None)

    def prune_spoof_fix(self, duplicate=False):
        if duplicate:
            info = FinderPrune.duplicate(self)
            info.prune_spoof_fix(duplicate=False)
            return info
        self.prune_spoofing()
        self.fixfours()

    def tripaddrs(self):
        return {a for t in self.triplets for a in t}

    def tripprev(self):
        prev = defaultdict(set)
        for w, x, y in self.triplets:
            prev[x].add(w)
        return prev

class FinderPruneContainer(dict):
    @classmethod
    def default(cls):
        return cls()

    def reduce(self):
        info = FinderPrune()
        for vpinfo in self.values():
            info.update(vpinfo)
        return info

    def dump(self, filename):
        d = {vp: info.dumps() for vp, info in self.items()}
        with open(filename, 'wb') as f:
            pickle.dump(d, f)

    @classmethod
    def load(cls, filename):
        with open(filename, 'rb') as f:
            infos = pickle.load(f)
        container = cls()
        for k, v in infos.items():
            container[k] = FinderPrune.loads(v)
        return container

    def trace_output(self, directory, skips=None):
        if directory:
            os.makedirs(directory, exist_ok=True)
        for vp, info in self.items():
            skip = skips[vp] if skips is not None and vp in skips else None
            targets = {otherside(addr, 2) for addr in info.middletwos.keys() | info.lasttwos.keys()}
            targets |= {otherside(addr, 4) for addr in info.middlefours.keys() | info.lastfours.keys()}
            if skip is not None:
                targets -= skip
            if targets:
                with open(os.path.join(directory, '{}.addrs'.format(vp)), 'w') as f:
                    f.writelines('{}\n'.format(target) for target in targets)

def create_pairs(cands, subnet, num=False):
    for x in cands:
        y = otherside(x, subnet)
        if num:
            yield x, y, cands[x]
        else:
            yield x, y

def otherside(addr, n):
    try:
        return otherside_err(addr, n)
    except:
        return None

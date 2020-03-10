import re
import sys
from collections import namedtuple, Counter
from os.path import basename
from typing import Set, Dict, Tuple

from traceutils.as2org.as2org import AS2Org
from traceutils.ixps.ixps import PeeringDB
from traceutils.radix.ip2as import IP2AS

from alias import Alias
from finder_prune import FinderPrune
import pandas as pd


Row = namedtuple('Row', ['tp', 'fp', 'fn', 'tn', 'ppv', 'recall', 'total'])


def detect(addr, candidates, valid=None, trippairs=None, aliases=None, ixps=None):
    pos = False
    if addr in candidates.twos:
        pos = True
    elif addr in candidates.fours:
        if valid is None or addr not in valid or valid[addr] > 1:
            pos = True
        else:
            pos = False
    elif ixps is None or addr in ixps:
        pos = True
    if pos:
        if trippairs is not None and addr in trippairs:
            pairs = trippairs[addr]
            if all(w in aliases.nid and y in aliases.nid and aliases.nid[w] == aliases.nid[y] for w, y in pairs):
                # vi.aliases.add(addr)
                pos = False
    return pos


class VerifyInfo:
    def __init__(self):
        self.tps = set()
        self.fps = set()
        self.fns = set()
        self.tns = set()
        self.twos = set()
        self.fours = set()
        self.ixps = set()
        self.aliases = set()

    @property
    def tp(self):
        return len(self.tps)

    @property
    def tn(self):
        return len(self.tns)

    @property
    def fp(self):
        return len(self.fps)

    @property
    def fn(self):
        return len(self.fns)

    def __repr__(self):
        return 'TP {:,d} TN {:,d} FP {:,d} FN {:,d} PPV {:.2%} Recall {:.2%}'.format(self.tp, self.tn, self.fp, self.fn, self.ppv, self.recall)

    @property
    def ppv(self):
        denom = self.tp + self.fp
        if denom == 0:
            return float('nan')
        return self.tp / denom

    @property
    def recall(self):
        denom = self.tp + self.fn
        if denom == 0:
            return float('nan')
        return self.tp / denom

    @property
    def total(self):
        return self.tp + self.fp + self.fn + self.tn

    @property
    def row(self):
        return Row(self.tp, self.fp, self.fn, self.tn, self.ppv, self.recall, self.total)

    def series(self, **kwargs):
        s = pd.Series(self.row._asdict())
        for k, v in kwargs.items():
            s[k] = v
        return s


class Validate:

    def __init__(self, ip2as: IP2AS, as2org: AS2Org, peeringdb: PeeringDB):
        self.ip2as = ip2as
        self.as2org = as2org
        self.peeringdb = peeringdb

    def use_addr(self, addr: str, torg: str, prev: Dict[str, Set[str]], gtaddrs: Set[str]):
        if addr in prev:
            for x in prev[addr]:
                asn = self.ip2as[x]
                org = self.as2org[asn]
                if org == torg:
                    return True
                asn = self.peeringdb.addrs.get(x, 0)
                org = self.as2org[asn]
                if org == torg:
                    return True
                if x in gtaddrs:
                    return True
        return False

    def validate(self, alladdrs, candidates: FinderPrune, vpn, default, ixps, prev, tasn, valid=None, trippairs=None, aliases: Alias=None) -> VerifyInfo:
        # print('hello')
        vi = VerifyInfo()
        torg = self.as2org[tasn]
        gtaddrs = vpn | default
        addrs = gtaddrs & alladdrs
        for addr in addrs:
            pos = detect(addr, candidates, valid=valid, trippairs=trippairs, aliases=aliases, ixps=ixps)
            # pos = False
            # if addr in candidates.twos:
            #     pos = True
            # elif addr in candidates.fours:
            #     if valid is None or valid[addr] > 1:
            #         pos = True
            #     else:
            #         pos = False
            # elif addr in ixps:
            #     pos = True
            # if pos:
            #     if trippairs is not None and addr in trippairs:
            #         pairs = trippairs[addr]
            #         if all(w in aliases.nid and y in aliases.nid and aliases.nid[w] == aliases.nid[y] for w, y in pairs):
            #             vi.aliases.add(addr)
            #             pos = False
            if not self.use_addr(addr, torg, prev, gtaddrs):
                continue
            if addr in vpn or addr in ['163.253.70.1']:
                if pos:
                    vi.tps.add(addr)
                elif addr != '198.71.47.83':
                    vi.fns.add(addr)
            else:
                if pos:
                    vi.fps.add(addr)
                else:
                    vi.tns.add(addr)
        return vi


class ValidateIPs:

    def __init__(self, validate, candidates: FinderPrune, prev: Dict[str, Set[str]], valid: Dict[str, bool] = None, trippairs=None, aliases: Alias = None, alladdrs=None):
        self.val = validate
        self.candidates = candidates
        self.valid = valid
        self.prev = prev
        self.trippairs = trippairs
        self.aliases = aliases
        if alladdrs is not None:
            self.alladdrs = alladdrs
        else:
            self.alladdrs = candidates.alladdrs()
        self._middle = None
        self._middleecho = None

    @property
    def middle(self):
        if self._middle is None:
            self._middle = self.candidates.middle()
        return self._middle

    @property
    def middleecho(self):
        if self._middleecho is None:
            self._middleecho = self.candidates.middle_echo()
        return self._middleecho

    def validate(self, addrs, vpn, default, ixps, tasn):
        return self.val.validate(addrs, self.candidates, vpn, default, ixps, self.prev, tasn, valid=self.valid, trippairs=self.trippairs, aliases=self.aliases)

    def allval(self, vpn, default, ixps, tasn):
        return self.validate(self.alladdrs, vpn, default, ixps, tasn)

    def breakdown(self, vpn, default, ixps, tasn):
        allixps = self.candidates.ixpaddrs()
        val: VerifyInfo = self.validate(self.alladdrs, vpn, default, ixps, tasn)
        rows = []
        for addr in val.tps | val.fps | val.fns | val.tns:
            if addr in val.tps:
                res = 'tp'
            elif addr in val.fps:
                res = 'fp'
            elif addr in val.fns:
                res = 'fn'
            else:
                res = 'tn'
            if addr in self.candidates.twos:
                cat = 'twos'
            elif addr in self.candidates.fours:
                cat = 'fours'
            elif addr in allixps:
                cat = 'ixp'
            else:
                cat = 'invalid'
            rows.append([addr, res, cat])
        return pd.DataFrame(rows, columns=['addr', 'result', 'category'])

    def compare(self, vpn: Set[str], default: Set[str], ixps: Set[str], tasn: int, **kwargs):
        rows = [
            self.validate(self.alladdrs, vpn, default, ixps, tasn).series(vtype='all', **kwargs),
            self.validate(self.middleecho, vpn, default, ixps, tasn).series(vtype='middle', **kwargs)
        ]
        return pd.DataFrame(rows)

    def vrfinfo(self, ixps=None):
        return VRFInfo(self.candidates, self.valid, ixps, self.trippairs, self.aliases)


class VRFInfo:
    def __init__(self, candidates: FinderPrune, valid=None, ixps=None, trippairs=None, aliases=None):
        self.candidates = candidates
        self.valid = valid
        self.ixps = ixps
        self.trippairs = trippairs
        self.aliases = aliases
        self.middle = candidates.middle_echo()
        # self.middle = candidates.middle()
        self.vrf = {}

    def compute(self):
        self.vrf = {}
        ixpaddrs = self.candidates.ixpaddrs()
        for a in self.candidates.fours | self.candidates.twos | ixpaddrs:
            pos = detect(a, self.candidates, self.valid, self.trippairs, self.aliases, self.ixps)
            if pos:
                if a in self.candidates.twos:
                    self.vrf[a] = 'two'
                elif a in self.candidates.fours:
                    self.vrf[a] = 'four'
                elif a in ixpaddrs:
                    self.vrf[a] = 'ixp'
                # else:
                #     print(a)
            # else:
            #     print(a)

    # def compute(self):
    #     self.vrf = {}
    #     ixpaddrs = self.candidates.ixpaddrs()
    #     for a in self.middle:
    #         pos = detect(a, self.candidates, self.valid, self.trippairs, self.aliases, self.ixps)
    #         if pos:
    #             if a in self.candidates.twos:
    #                 self.vrf[a] = 'two'
    #             elif a in self.candidates.fours:
    #                 self.vrf[a] = 'four'
    #             elif a in ixpaddrs:
    #                 self.vrf[a] = 'ixp'
    #             else:
    #                 print(a)
    #         # else:
    #         #     print(a)

    @property
    def percent(self):
        if not self.vrf:
            print('Warning: run compute() first', file=sys.stderr)
            return float('nan')
        return len(self.vrf.keys() & self.middle) / len(self.middle)

    def row(self, name=None):
        c = Counter(self.vrf.values())
        twos = c['two']
        fours = c['four']
        ixps = c['ixp']
        total = len(self.vrf)
        crow = self.candidates.row()
        d = {'twos': twos, 'fours': fours, 'foursd': 1 - (fours / crow['fours']), 'ixps': ixps, 'ixpd': 1 - (ixps / crow['ixps']), 'total': total, 'totalp': total / len(self.middle)}
        if name is not None:
            d['name'] = name
        return d


class VPInfo:
    def __init__(self):
        self.vpdata = pd.read_html('https://www.caida.org/projects/ark/locations/')[0]
        city = self.vpdata.City.str.rpartition(', ', expand=True)
        self.vpdata['City'] = city[0]
        self.vpdata['Country'] = city[2]
        self.vps = set(self.vpdata.Name)

    def get_vps(self, filename):
        vps = set()
        with open(filename) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # print(line)
                # break
                base = basename(line)
                vp = base.partition('.')[0]
                if vp not in self.vps:
                    m = re.search(r'\.([-a-z0-9]+)\.warts', base)
                    if m:
                        vp = m.group(1)
                    else:
                        print(line)
                vps.add(vp)
        return vps

    def info(self, filename, df=False):
        vps = self.get_vps(filename)
        vpdata = self.vpdata[self.vpdata.Name.isin(vps)]
        if df:
            return vpdata
        return vpdata.agg({'Name': 'nunique', 'AS Number': 'nunique', 'City': 'nunique', 'Country': 'nunique'})

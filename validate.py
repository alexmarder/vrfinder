import re
import sys
from collections import namedtuple, Counter
from os.path import basename
from typing import Set, Dict

from traceutils.as2org.as2org import AS2Org
from traceutils.ixps.ixps import PeeringDB
from traceutils.radix.ip2as import IP2AS

from finder import CandidateInfo
import pandas as pd


Row = namedtuple('Row', ['tp', 'fp', 'fn', 'tn', 'ppv', 'recall', 'total'])


class VerifyInfo:
    def __init__(self):
        self.tps = set()
        self.fps = set()
        self.fns = set()
        self.tns = set()
        self.twos = set()
        self.fours = set()
        self.ixps = set()

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

    def validate(self, alladdrs, candidates: CandidateInfo, valid, vpn, default, ixps, prev, tasn):
        # print('hello')
        vi = VerifyInfo()
        torg = self.as2org[tasn]
        gtaddrs = vpn | default
        addrs = gtaddrs & alladdrs
        for addr in addrs:
            pos = False
            # if addr == '2001:468:f000:2707::1':
            #     print('here')
            if addr in candidates.twos:
                pos = True
            elif addr in candidates.fours:
                if valid[addr] > 1:
                    pos = True
                else:
                    pos = False
                # if addr == '2001:468:f000:2707::1':
                #     print(pos)
            elif addr in ixps:
                pos = True
            if not self.use_addr(addr, torg, prev, gtaddrs):
                continue
            if addr in vpn or addr in ['163.253.70.1']:
                if pos:
                    vi.tps.add(addr)
                elif addr != '198.71.47.83':
                    # if prev[addr] & vpn:
                    # if any(x in gtaddrs for x in prev[addr]):
                    vi.fns.add(addr)
            else:
                if pos:
                    vi.fps.add(addr)
                else:
                    vi.tns.add(addr)
        return vi


def validate(alladdrs, candidates: CandidateInfo, valid, vpn, default, ixps, prev):
    # print('hello')
    vi = VerifyInfo()
    gtaddrs = vpn | default
    addrs = gtaddrs & alladdrs
    for addr in addrs:
        pos = False
        # if addr == '2001:468:f000:2707::1':
        #     print('here')
        if addr in candidates.twos:
            pos = True
        elif addr in candidates.fours:
            if valid[addr] > 1:
                pos = True
            else:
                pos = False
            # if addr == '2001:468:f000:2707::1':
            #     print(pos)
        elif addr in ixps:
            pos = True
        if not (addr in prev and prev[addr] & vpn):
            continue
        if addr in vpn or addr in ['163.253.70.1']:
            if pos:
                vi.tps.add(addr)
            elif addr in prev and addr != '198.71.47.83':
                # if prev[addr] & vpn:
                # if any(x in gtaddrs for x in prev[addr]):
                    vi.fns.add(addr)
        else:
            if pos:
                vi.fps.add(addr)
            else:
                vi.tns.add(addr)
    return vi


class VRFInfo:
    def __init__(self, candidates: CandidateInfo):
        self.candidates = candidates
        self.middle = candidates.middle_echo()
        self.vrf = {}

    def compute(self, valid, ixps):
        self.vrf = {}
        for a in self.middle:
            if a in self.candidates.twos:
                self.vrf[a] = 'two'
            elif a in self.candidates.fours:
                if valid[a] > 1:
                    self.vrf[a] = 'four'
            elif a in ixps:
                self.vrf[a] = 'ixp'

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

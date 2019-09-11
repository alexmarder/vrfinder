import pickle
from collections import defaultdict
from multiprocessing.pool import Pool
from typing import List, Set

from traceutils.as2org.as2org import AS2Org
from traceutils.bgp.bgp import BGP
from traceutils.progress.bar import Progress
from traceutils.radix.ip2as import IP2AS
from traceutils.scamper.hop import ICMPType
from traceutils.scamper.warts import WartsReader
from traceutils.utils.net import otherside


class LastCand:

    def __init__(self):
        self.middle = set()
        self.pasns = set()
        self.dasns = set()

    def __repr__(self):
        return 'M {:,d} P {:,d} D {:,d}'.format(len(self.middle), len(self.pasns), len(self.dasns))

    def update(self, info):
        self.middle.update(info.middle)
        self.pasns.update(info.pasns)
        self.dasns.update(info.dasns)


class Prune:

    def __init__(self, ip2as: IP2AS, as2org: AS2Org, bgp: BGP, *infos: List[LastCand]):
        self.ip2as = ip2as
        self.as2org = as2org
        self.bgp = bgp
        self.pasns = defaultdict(set)
        self.dasns = defaultdict(set)
        self.toprobe = None
        if infos:
            pb = Progress(len(infos), 'Merging infos', callback=self.__repr__)
            for info in pb.iterator(infos):
                self.simplify(info)

    def __repr__(self):
        plen = 0 if self.pasns is None else len(self.pasns)
        dlen = 0 if self.dasns is None else len(self.dasns)
        tlen = 0 if self.toprobe is None else len(self.toprobe)
        return 'P {:,d} D {:,d} T {:,d}'.format(plen, dlen, tlen)

    def dump(self, filename):
        d = {'pasns': dict(self.pasns), 'dasns': dict(self.dasns), 'toprobe': self.toprobe}
        with open(filename, 'wb') as f:
            pickle.dump(d, f)

    def load(self, filename):
        with open(filename, 'rb') as f:
            d = pickle.load(f)
            self.pasns = d['pasns']
            self.dasns = d['dasns']

    def simplify(self, info):
        for addr, pasn in info.pasns:
            if addr not in info.middle:
                self.pasns[addr].add(pasn)
        for addr, dasn in info.dasns:
            if addr not in info.middle:
                self.dasns[addr].add(dasn)

    def dasn_filter(self, dasns):
        if len(dasns) <= 1:
            return True
        for x in dasns:
            xorg = self.as2org[x]
            if all(y == x or self.bgp.provider_rel(x, y) or xorg == self.as2org[y] for y in dasns):
                return True
        return False

    def remove_same(self):
        self.toprobe = set()
        pb = Progress(len(self.pasns), 'Filtering', increment=100000, callback=lambda: '{:,d}'.format(len(self.toprobe)))
        for addr, pasns in pb.iterator(self.pasns.items()):
            dasns = self.dasns[addr]
            # dorgs = {self.as2org[a] for a in self.dasns[addr]}
            if self.dasn_filter(dasns):
                asn = self.ip2as[addr]
                if asn not in dasns:
                    self.toprobe.add(addr)
                elif asn not in pasns:
                    self.toprobe.add(addr)


class WartsFile:
    def __init__(self, filename, monitor):
        self.filename = filename
        self.monitor = monitor

    def __repr__(self):
        return 'Warts<{}, {}>'.format(self.filename, self.monitor)


def candidates_parallel(filenames: List[WartsFile], ip2as=None, poolsize=40):
    global _ip2as
    if ip2as is not None:
        _ip2as = ip2as
    infos = defaultdict(LastCand)
    files = [wf.filename for wf in filenames]
    pb = Progress(len(filenames), message='Reading last info')
    with Pool(min(poolsize, len(filenames))) as pool:
        for wf, newinfo in pb.iterator(zip(filenames, pool.imap(candidates, files))):
            infos[wf.monitor].update(newinfo)
    return infos


def candidates(filename: str, ip2as=None, info: LastCand = None):
    global _ip2as
    if ip2as is not None:
        _ip2as = ip2as
    if info is None:
        info = LastCand()
    with WartsReader(filename) as f:
        for trace in f:
            if trace.hops:
                trace.prune_private(_ip2as)
                if trace.hops:
                    trace.prune_dups()
                    trace.prune_loops()
                    if trace.hops:
                        hops = trace.hops
                        if hops[-1].addr == trace.dst:
                            hops = hops[:-1]
                        #     dasn = 0
                        # else:
                        #     dasn = _ip2as[trace.dst]
                        if hops:
                            dasn = _ip2as[trace.dst]
                            laddr = hops[-1].addr
                            if dasn > 0:
                                info.dasns.add((laddr, dasn))
                            if len(hops) > 1:
                                pasn = _ip2as[hops[-2].addr]
                                info.pasns.add((laddr, pasn))
                            for hop in hops[:-1]:
                                addr = hop.addr
                                info.middle.add(addr)
    return info


def read_responses(filename):
    responses = set()
    with WartsReader(filename) as f:
        for ping in f:
            if any(r.type == ICMPType.echo_reply for r in ping.responses):
                responses.add(ping.dst)
    return responses


def read_pings(filenames: List[WartsFile], poolsize=40):
    files = [wf.filename for wf in filenames]
    responses = {}
    pb = Progress(len(files), 'Reading pings')
    with Pool(poolsize) as pool:
        for wf, newresponses in pb.iterator(zip(filenames, pool.imap_unordered(read_responses, files))):
            responses[wf.monitor] = newresponses
    return responses


class LastPings:

    def __init__(self, toprobe: Set[str]):
        self.toprobe2 = toprobe
        self.addrs2 = None
        self.resps2 = None
        self.toprobe4 = None
        self.addrs4 = None
        self.resps4 = None
        self.addrs = None
        self.resps = None

    def subnet2(self, filenames, poolsize=40):
        self.addrs2 = set()
        self.resps2 = read_pings(filenames, poolsize=poolsize)
        for resps in self.resps2.values():
            self.addrs2.update(resps)
        self.toprobe4 = self.toprobe2 - {otherside(a, 2) for a in self.addrs2}

    def subnet4(self, filenames, poolsize=40):
        self.addrs4 = set()
        self.resps4 = read_pings(filenames, poolsize=poolsize)
        for resps in self.resps4.values():
            self.addrs4.update(resps)

    def trace_probe(self):
        self.addrs = self.addrs2 | self.addrs4
        self.resps = {}
        vps = self.resps2.keys() | self.resps4.keys()
        for vp in vps:
            addrs2 = self.resps2.get(vp, set())
            addrs4 = self.resps4.get(vp, set())
            self.resps[vp] = addrs2 | addrs4

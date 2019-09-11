from collections import defaultdict
from multiprocessing.pool import Pool

from traceutils.alias.alias import Alias
from traceutils.as2org.as2org import AS2Org
from traceutils.ixps.ixps import PeeringDB
from traceutils.progress.bar import Progress
from traceutils.radix.ip2as import IP2AS
from traceutils.scamper.hop import ICMPType
from traceutils.scamper.warts import WartsReader
from traceutils.utils.net import prefix_addrs

from candidate_info import CandidateInfo


def read_responses(filename):
    responses = defaultdict(bool)
    with WartsReader(filename) as f:
        for ping in f:
            resp = any(r.type == ICMPType.echo_reply for r in ping.responses)
            responses[ping.dst] |= resp
    return responses


def aliases(filename):
    responses = defaultdict(bool)
    with WartsReader(filename) as f:
        for ping in f:
            resp = float('nan')
            for r in ping.responses:
                if r.type == ICMPType.echo_reply:
                    resp = r.reply_ttl
                    break
            responses[ping.dst] = resp
    return responses, filename


def read_aliases(files, poolsize=35):
    reply_ttls = defaultdict(dict)
    pb = Progress(len(files), 'Reading pings')
    with Pool(poolsize) as pool:
        for responses, filename in pb.iterator(pool.imap_unordered(aliases, files)):
            for a, b in responses.items():
                reply_ttls[a][filename] = b
    reply_ttls.default_factory = None
    return reply_ttls


class Prune:

    def __init__(self, info: CandidateInfo, as2org: AS2Org, peeringdb: PeeringDB, aliases: Alias):
        self.info = info
        self.as2org = as2org
        self.peeringdb = peeringdb
        self.ixps = None
        self.responses = None
        self.reply_ttls = None
        self.fours = None
        self.trippairs = self.info.trippairs()
        self.aliases = aliases
        self.forwarding = None

    def aliasprune(self):
        self.forwarding = set()
        cfas = self.ixps | self.fours | self.info.twos
        pb = Progress(len(cfas), 'Pruning router loops', increment=100000, callback=lambda: '{:,d}'.format(len(self.forwarding)))
        for addr in pb.iterator(cfas):
            if addr in self.trippairs:
                pairs = self.trippairs[addr]
                if not all(w in self.aliases.nids and y in self.aliases.nids and self.aliases.nids[w] == self.aliases.nids[y] for w, y in pairs):
                    self.forwarding.add(addr)
            else:
                self.forwarding.add(addr)

    def ixpprune(self):
        self.ixps = set()
        pasns = self.info.ixpprev()
        pb = Progress(len(pasns), 'Pruning IXPs', increment=100000, callback=lambda: '{:,d}'.format(len(self.ixps)))
        for x, asns in pb.iterator(pasns.items()):
            if x in self.peeringdb.addrs:
                asn = self.peeringdb.addrs[x]
                org = self.as2org[asn]
                orgs = {self.as2org[asn] for asn in asns if asn is not None}
                if org in orgs:
                    self.ixps.add(x)
            else:
                pass

    def test_four(self, a):
        w, x, y, z = prefix_addrs(a, 2)
        b = y if x == a else y
        if self.responses[w] or self.responses[z]:
            return 1
        if self.responses[x] and self.responses[y]:
            return 2
        if self.responses[a]:
            return 3
        if self.responses[b]:
            return 5
        else:
            return 4

    def foursprune(self, ipv4=True, ipv6=True):
        self.fours = set()
        fours = self.info.fours
        if not ipv4:
            fours = {a for a in fours if ':' in a}
        if not ipv6:
            fours = {a for a in fours if ':' not in a}
        pb = Progress(len(fours), 'Pruning Fours', increment=100000,
                      callback=lambda: '{:,d}'.format(len(self.fours)))
        for addr in pb.iterator(fours):
            if self.test_four(addr) > 1:
                self.fours.add(addr)

    def read_responses(self, files, poolsize=35):
        self.responses = defaultdict(bool)
        pb = Progress(len(files), 'Reading pings')
        with Pool(poolsize) as pool:
            for responses in pb.iterator(pool.imap_unordered(read_responses, files)):
                for a, b in responses.items():
                    self.responses[a] |= b
        self.responses.default_factory = None

    def read_aliases(self, files, poolsize=35):
        self.reply_ttls = defaultdict(dict)
        pb = Progress(len(files), 'Reading pings')
        with Pool(poolsize) as pool:
            for responses, filename in pb.iterator(pool.imap_unordered(aliases, files)):
                for a, b in responses.items():
                    self.reply_ttls[a][filename] = b
        self.reply_ttls.default_factory = None

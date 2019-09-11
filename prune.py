import os
from argparse import ArgumentParser
from collections import defaultdict
from multiprocessing.pool import Pool

from traceutils.alias.alias import Alias
from traceutils.as2org.as2org import AS2Org
from traceutils.ixps.ixps import PeeringDB
from traceutils.progress.bar import Progress
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
        if a not in self.responses:
            return 6
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


def write_fours(candidates, args):
    
    os.makedirs(args.output_dir, exist_ok=True)


def prune(candidates, args):
    pass


def main():
    parser = ArgumentParser()
    parser.add_argument('-c', '--candidates', required=True)
    subparsers = parser.add_subparsers()
    parser_fours = subparsers.add_parser('fours', help='Write potential four-address subnet CFAs to file and exit.')
    parser_fours.add_argument('-o', '--output-dir', required=True, help='Directory where output files will be written.')
    parser_fours.set_defaults(func=write_fours)
    parser_prune = subparsers.add_parser('prune', help='Prune the CFAs and dump final forwarding addresses and prior address space.')
    parser_prune.add_argument('-i', '--ip2as', required=True)
    parser_prune.add_argument('-p', '--peeringdb', required=True)
    parser_prune.add_argument('-l', '--lasts')
    parser_prune.add_argument('-a', '--aliases')
    parser_prune.add_argument('-f', 'files', help='Warts files from the ping test.')
    parser_prune.add_argument('-o', 'outfile')
    parser_prune.set_defaults(func=prune)
    args = parser.parse_args()

    info = CandidateInfo.load(args.candidates)
    args.func(info, args)

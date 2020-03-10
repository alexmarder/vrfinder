import re
from collections import defaultdict
from itertools import chain

import networkx as nx

from traceutils.file2.file2 import fopen
from traceutils.progress import Progress
from traceutils.utils.net import valid


def extract_regex(lines):
    regexes = {}
    for line in lines:
        first, *_ = line.partition(',')
        domain, *regex = first.split()
        regexes[domain[:-1]] = re.compile('|'.join(regex))
    return regexes

def extract_regex_file(filename):
    with open(filename) as f:
        return extract_regex(f)

def match_asns(regexes, names):
    asns = {}
    pb = Progress(len(names), 'testing', increment=100000, callback=lambda: '{:,d}'.format(len(asns)))
    for addr, name in pb.iterator(names.items()):
        for domain, regex in regexes.items():
            if domain == 'comcast.net':
                continue
            if name.endswith(domain):
                m = regex.match(name)
                if m:
                    asn = int([a for a in m.groups() if a is not None][0])
                    if valid(asn):
                        asns[addr] = asn
    return asns

def match_routers(regexes, names):
    routers = {}
    pb = Progress(len(names), 'testing', increment=10000, callback=lambda: '{:,d}'.format(len(routers)))
    for addr, name in pb.iterator(names.items()):
        for domain, regex in regexes.items():
            if name.endswith(domain):
                m = regex.match(name)
                if m:
                    matches = [a for a in m.groups() if a is not None]
                    if not matches:
                        continue
                    router = matches[0]
                    routers[addr] = router
    return routers

class Regexes:
    def __init__(self):
        self.names = None
        self.regexes = None
        self.routers = None

    def read_names(self, filename):
        names = {}
        with fopen(filename) as f:
            for line in f:
                try:
                    _, addr, name = line.split()
                except ValueError:
                    continue
                names[addr] = name
        self.names = names

    def extract_regexes(self, filename):
        self.regexes = extract_regex_file(filename)

    def match_routers(self):
        self.routers = match_routers(self.regexes, self.names)

    def graph(self):
        nodes = self.getnodes()
        g = nx.Graph()
        for addrs in nodes.values():
            nx.add_path(g, addrs)
        return g

    def merge(self, filename, output=None):
        g = self.graph()
        skip = []
        pb = Progress(increment=500000, callback=lambda: 'Skip {:,d}'.format(len(skip)))
        with fopen(filename, 'rt') as f:
            for line in pb.iterator(f):
                if line[0] == '#':
                    continue
                _, nid, *addrs = line.split()
                if any(a in self.routers for a in addrs):
                    nx.add_path(g, addrs)
                else:
                    skip.append(addrs)
        if output:
            with fopen(output, 'wt') as f:
                pb = Progress(increment=1000000)
                for nid, node in pb.iterator(enumerate(chain(nx.connected_components(g), skip), 1)):
                    addrs = ' '.join(node)
                    f.write('node N{nid}:  {addrs}\n'.format(nid=nid, addrs=addrs))
        return g

    def getnodes(self):
        nodes = defaultdict(list)
        for addr, router in self.routers.items():
            nodes[router].append(addr)
        return nodes

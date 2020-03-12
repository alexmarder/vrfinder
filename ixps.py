import json
import os
from collections import defaultdict


class IX:
    def __init__(
            self, pch_id=None, name=None, country=None, region=None, alternatenames=None, sources=None,
            prefixes=None, pdb_id=None, url=None, pdb_org_id=None, state=None, ix_id=None, org_id=None,
            geo_id=None, latitude=None, longitude=None, **kwargs
    ):
        self.pch_id = pch_id
        self.name = name
        self.country = country
        self.region = region
        self.alternatenames = alternatenames
        self.sources = sources
        self.prefixes = prefixes
        self.pdb_id = pdb_id
        self.url = url
        self.pdb_org_id = pdb_org_id
        self.state = state
        self.ix_id = ix_id
        self.org_id = org_id
        self.geo_id = geo_id
        self.latitude = latitude
        self.longitude = longitude
        for k, v in kwargs.items():
            setattr(self, k, v)

class IXPs:
    def __init__(self):
        self.ixs = None
        self.addrs = None

    def read_ixs(self, filename):
        ixs = {}
        with open(filename) as f:
            for line in f:
                if line[0] != '#':
                    j = json.loads(line)
                    ix = IX(**j)
                    ixs[ix.ix_id] = ix
        self.ixs = ixs

    def read_ix_asns(self, filename):
        addrs = defaultdict(set)
        with open(filename) as f:
            for line in f:
                if line[0] != '#':
                    j = json.loads(line)
                    asn = j['asn']
                    for addr in j['ipv4']:
                        addrs[addr].add(asn)
                    for addr in j['ipv6']:
                        addrs[addr].add(asn)
        self.addrs = addrs

from multiprocessing.pool import ThreadPool

import requests
from traceutils.progress.bar import Progress
from traceutils.radix.ip2as import IP2AS


def retrieve_subnet(ixid):
    subnets = []
    r = requests.get('https://www.pch.net/api/ixp/subnets/{}'.format(ixid))
    if r.ok:
        for info in r.json():
            if 'subnet' in info:
                subnets.append(info['subnet'])
    return subnets, ixid


class PCH:
    def __init__(self):
        r = requests.get('https://www.pch.net/api/ixp/directory/active')
        if not r.ok:
            raise Exception('Should be ok')
        self.directory = r.json()
        self.ixids = {int(ix['id']) for ix in self.directory}
        self.subnets = {}

    def retrieve_subnets(self, poolsize=5):
        pb = Progress(len(self.ixids), 'Retrieving subnets', callback=lambda: '{:,d}'.format(len(self.subnets)))
        with ThreadPool(poolsize) as pool:
            for subnets, ixid in pb.iterator(pool.imap_unordered(retrieve_subnet, self.ixids)):
                for subnet in subnets:
                    subnet = subnet.strip()
                    if subnet:
                        self.subnets[subnet] = ixid

    def retrieve_addrs(self, poolsize=5):
        pb = Progress(len(self.ixids), 'Retrieving subnets', callback=lambda: '{:,d}'.format(len(self.subnets)))
        with ThreadPool(poolsize) as pool:
            for subnets, ixid in pb.iterator(pool.imap_unordered(retrieve_subnet, self.ixids)):
                for subnet in subnets:
                    self.subnets[subnet] = ixid

    def create_trie(self):
        ip2as = IP2AS()
        for subnet, ixid in self.subnets.items():
            # print(type(ixid))
            ip2as.add(subnet, asn=ixid)
        return ip2as

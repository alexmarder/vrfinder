#!/usr/bin/env python
from argparse import ArgumentParser
from itertools import islice

import netaddr
from lxml import etree
from traceutils.radix.ip2as import IP2AS


def print_addrs(filename):
    ip2as = IP2AS()
    ip2as.add_private()
    parser = etree.XMLParser(ns_clean=True, recover=True)
    root = etree.parse(filename, parser)
    ifads = root.findall('.//{*}ifa-destination')
    seen = set()
    for ifad in ifads:
        if ifad is not None:
            net = ifad.text
            _, _, prefixlen = net.partition('/')
            if prefixlen:
                prefixlen = int(prefixlen)
                if prefixlen > 16:
                    node = ip2as.search_best_prefix(net)
                    if node and node.asn < 0:
                        continue
                    if net in seen:
                        continue
                    seen.add(net)
                    for host in islice(netaddr.IPNetwork(net).iter_hosts(), 2):
                        print('"{}"'.format(str(host)))


def main():
    parser = ArgumentParser()
    parser.add_argument('filename')
    args = parser.parse_args()
    print_addrs(args.filename)


if __name__ == '__main__':
    main()

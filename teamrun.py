#!/usr/bin/env python
import os
from argparse import ArgumentParser

import finder

v1dates = [
    [2011, 4, 30], [2011, 10, 30], [2012, 7, 31], [2013, 4, 30], [2013, 7, 31], [2014, 4, 30], [2014, 12, 31],
    [2015, 8, 31],
    [2016, 3, 14]
]

v2dates = [
    [2016, 9, 30], [2017, 1, 31], [2017, 8, 31], [2018, 2, 28]
]

jsondates = [
    [2019, 1, 31], [2019, 4, 30]
]

prefixv1 = [[2016, 1, 31]]
prefixv2 = [[2016, 7, 31], [2017, 1, 31], [2017, 7, 31], [2018, 1, 31]]
prefixj = [[2018, 7, 31], [2019, 1, 31], [2019, 7, 31]]

def prep_dates(type):
    if type == 'team':
        v1 = v1dates
        v2 = v2dates
        v3 = jsondates
    elif type == 'prefix':
        v1 = prefixv1
        v2 = prefixv2
        v3 = prefixj
    else:
        raise Exception('Incorrect type: {}'.format(type))
    v1 = [r + [1] for r in v1]
    v2 = [r + [2] for r in v2]
    v3 = [r + [3] for r in v3]
    return v1 + v2 + v3

def pdbfile(year, month, day, version):
    if version == 1:
        pdb = '/data/external/peeringdb-dumps/v1/{year}/{month:02d}/peeringdb_dump_{year}_{month:02d}_{day:02d}.sqlite'
    elif version == 2:
        pdb = '/data/external/peeringdb-dumps/{year}/{month:02d}/peeringdb_2_dump_{year}_{month:02d}_{day:02d}.sqlite'
    else:
        pdb = '/data/external/peeringdb-dumps/{year}/{month:02d}/peeringdb_2_dump_{year}_{month:02d}_{day:02d}.json'
    return pdb.format(year=year, month=month, day=day)

def main():
    parser = ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--team', action='store_true')
    group.add_argument('--prefix', action='store_true')
    parser.add_argument('--dir', required=True)
    args, extra = parser.parse_known_args()
    os.makedirs(args.dir, exist_ok=True)
    for year, month, day, version in prep_dates('team' if args.team else 'prefix'):
        pdb = pdbfile(year, month, day, version)
        argv = '-f prefixtest/{year}{month:02d}.files -I {pdb} -o {dir}/{year}{month:02d}.rttls.pickle'.format(year=year, month=month, day=day, pdb=pdb, dir=args.dir)
        print(argv.split() + extra)
        finder.main(argv.split() + extra)

if __name__ == '__main__':
    main()

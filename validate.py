import pickle
import re
import sys
from collections import namedtuple, Counter
from os.path import basename
from typing import Set, Dict, Tuple

import numpy as np

from traceutils.as2org.as2org import AS2Org
from traceutils.file2 import fopen
from traceutils.ixps.ixps import PeeringDB
from traceutils.progress.bar import Progress
from traceutils.radix.ip2as import IP2AS

from alias import Alias
from finder_prune import FinderPrune
import pandas as pd


Row = namedtuple('Row', ['tp', 'fp', 'fn', 'tn', 'ppv', 'recall', 'total'])
Result = namedtuple('Result', ['addr', 'res', 'cat'])

class Validate:
    def __init__(self, ip2as: IP2AS, as2org: AS2Org, peeringdb: PeeringDB):
        self.ip2as = ip2as
        self.as2org = as2org
        self.peeringdb = peeringdb

    def validate(self, info: FinderPrune, vpns, dfns, prevs, asn, **kwargs):
        org = self.as2org[asn]
        results = []
        middle = info.middle_cfas()
        last = info.last_cfas()
        echo = info.echo_cfas()
        lastaddrs = {a for a, _ in info.last}
        for addr in vpns:
            if not (addr in info.middle or addr in lastaddrs):
                continue
            if addr in middle:
                results.append(Result(addr, 'tp', 'm'))
            elif addr in last:
                results.append(Result(addr, 'tp', 'l'))
            elif addr in echo:
                results.append(Result(addr, 'tp', 'e'))
            elif addr in info.ixpcfas:
                results.append(Result(addr, 'tp', 'x'))
            else:
                if addr in prevs:
                    if any(self.as2org[self.ip2as[a]] == org or a in vpns or a in dfns for a in prevs[addr]):
                        results.append(Result(addr, 'fn', 'f'))
        for addr in dfns:
            if addr in middle:
                results.append(Result(addr, 'fp', 'm'))
            elif addr in last:
                results.append(Result(addr, 'fp', 'l'))
            elif addr in echo:
                results.append(Result(addr, 'fp', 'e'))
            elif addr in info.ixpcfas:
                results.append(Result(addr, 'fp', 'x'))
            else:
                results.append(Result(addr, 'tn', 't'))
        df = pd.DataFrame(results)
        for k, v in kwargs.items():
            df[k] = v
        return df

    def validate_multi(self, info: FinderPrune, vpns: Dict[str, Set[str]], dfns: Dict[str, Set[str]], prevs, asns: Dict[str, int]):
        dfs = []
        keys = vpns.keys() | dfns.keys()
        for key in keys:
            vpn = vpns.get(key, set())
            dfn = dfns.get(key, set())
            asn = asns.get(key, -1)
            df = self.validate(info, vpn, dfn, prevs, asn)
            df['dataset'] = key
            dfs.append(df)
        return pd.concat(dfs, ignore_index=True)

def load_prevs(file, vaddrs):
    with open(file, 'rb') as f:
        prevs = pickle.load(f)
    return {k: v for k, v in prevs.items() if k in vaddrs}

def load_prevs_tsv(file, vaddrs):
    prevs = {}
    pb = Progress(message='Reading {}'.format(file), increment=1000000, callback=lambda: '{:,d}'.format(len(prevs)))
    with fopen(file, 'rt') as f:
        for line in pb.iterator(f):
            y, xs = line.split()
            if y in vaddrs:
                prevs[y] = xs.split(',')
    return prevs

def load_addrs_tsv(file):
    addrs = set()
    pb = Progress(message='Reading {}'.format(file), increment=1000000, callback=lambda: '{:,d}'.format(len(addrs)))
    with fopen(file, 'rt') as f:
        for line in pb.iterator(f):
            y, xs = line.split()
            addrs.add(y)
            addrs.update(xs.split(','))
    return addrs

def summarize(df, **kwargs):
    rows = []
    for dataset, g in df.groupby('dataset'):
        d = dict(g.res.value_counts())
        tp = d.get('tp', 0)
        fp = d.get('fp', 0)
        fn = d.get('fn', 0)
        tn = d.get('tn', 0)
        ppv = tp / (tp + fp) if tp + fp > 0 else np.nan
        tpr = tp / (tp + fn) if tp + fn > 0 else np.nan
        d = {'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn, 'ppv': ppv, 'tpr': tpr, 'dataset': dataset}
        # d['ppv'] = ppv
        # d['tpr'] = tpr
        # d['dataset'] = dataset
        rows.append(d)
    df = pd.DataFrame(rows)
    for k, v in kwargs.items():
        df[k] = v
    return df

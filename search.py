from multiprocessing.pool import Pool
from typing import List

from traceutils.progress.bar import Progress
from traceutils.scamper.hop import Trace
from traceutils.scamper.warts import WartsReader

from finder import WartsFile

xtest = None
ytest = None

def search_dst(filename, dst):
    with WartsReader(filename) as f:
        for trace in f:
            if trace.dst == dst:
                return trace

def search(filename, ip2as=None):
    global _ip2as
    if ip2as is not None:
        _ip2as = ip2as
    # xtest = '12.226.90.10'
    # ytest = '12.226.90.11'
    with WartsReader(filename) as f:
        for trace in f:
            if trace.hops:
                addrs = trace.addrs()
                if xtest in addrs and ytest in addrs:
                    return trace
                continue
                # if xtest in addrs and _ip2as[trace.dst] == ytest:
                #     return trace
                # continue
                # if not (xtest in addrs and ytest in addrs):
                #     continue
                # i = 0
                # j = 0
                # for k, h in enumerate(trace.hops):
                #     if h.addr == xtest:
                #         i = k
                #     elif h.addr == ytest:
                #         j = k
                #     if i and j and i < j:
                #         return trace
                # return trace
                trace.prune_private(_ip2as)
                if trace.hops:
                    # trace.prune_dups()
                    trace.prune_loops()
                    packed = [hop.set_packed() for hop in trace.hops]
                    for i in range(len(packed) - 1):
                        x = trace.hops[i]
                        y = trace.hops[i + 1]
                        xaddr = x.addr
                        yaddr = y.addr
                        if xaddr == xtest and yaddr == ytest:
                            if x.probe_ttl == y.probe_ttl - 1:
                                if i > 0:
                                    w = trace.hops[i - 1]
                                else:
                                    w = None
                                if not w or w.reply_ttl != y.reply_ttl:
                                    return trace
    return None


def search_parallel(filenames: List[WartsFile], x, y, ip2as=None, poolsize=35):
    global _ip2as, xtest, ytest
    xtest = x
    ytest = y
    if ip2as is not None:
        _ip2as = ip2as
    files = [wf.filename for wf in filenames]
    pb = Progress(len(filenames), message='Searching')
    with Pool(poolsize) as pool:
        for wf, trace in pb.iterator(zip(filenames, pool.imap(search, files))):
            if trace is not None:
                return wf, trace
    return None

def printtrace(trace: Trace, ip2as=None):
    for hop in trace.allhops:
        asn = ip2as[hop.addr] if ip2as is not None else 0
        print('{:02d}: {:15} {:10} {:2} {:2} {:3} {:5}'.format(hop.probe_ttl, hop.addr, asn, hop.icmp_type, hop.icmp_code, hop.reply_ttl, hop.reply_ipid))

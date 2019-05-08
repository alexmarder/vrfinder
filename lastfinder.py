from collections import defaultdict
from multiprocessing.pool import Pool
from os.path import basename
from typing import List

from traceutils.progress.bar import Progress
from traceutils.scamper.hop import ICMPType
from traceutils.scamper.warts import WartsReader

from candidate_info import CandidateInfo
from finder import are_adjacent, valid_pair


def candidates_parallel(files: List[str], poolsize=35):
    info = CandidateInfo()
    pb = Progress(len(files), message='', callback=info.__repr__)
    with Pool(poolsize) as pool:
        for newinfo in pb.iterator(pool.imap(candidates, files)):
            # if newinfo is not None:
            #     return newinfo
            # continue
            info.update(newinfo)
    return info


def candidates(filename):
    info = CandidateInfo()
    with WartsReader(filename) as f:
        for trace in f:
            if trace.stop_reason == 'COMPLETED':
                if len(trace.hops) >= 2:
                    x = trace.hops[-2]
                    y = trace.hops[-1]
                    xb = x.set_packed()
                    yb = y.set_packed()
                    xaddr = x.addr
                    yaddr = y.addr
                    if are_adjacent(xb, yb):
                        size = valid_pair(xb, yb)
                        if size != 0:
                            # if xaddr == '2001:468:f000:2707::1':
                            #     print(filename)
                            #     return trace
                            if size == -2 or size == 2:
                                info.twos.add(xaddr)
                            elif size == -4 or size == 4:
                                info.fours.add(xaddr)
                            info.tuples.add((xaddr, yaddr))
    # return None
    return info


def pingparser_parallel(files: List[str], poolsize=35):
    responses = defaultdict(set)
    pb = Progress(len(files), message='', callback=lambda: '{:,d}'.format(len(responses)))
    with Pool(poolsize) as pool:
        for vp, newresponses in pb.iterator(pool.imap(pingparser, files)):
            for addr in newresponses:
                responses[addr].add(vp)
    return responses


def pingparser(filename):
    responses = []
    with WartsReader(filename) as f:
        for ping in f:
            resp = any(r.type == ICMPType.echo_reply for r in ping.responses)
            if resp:
                responses.append(ping.dst)
    return basename(filename).partition('.')[0], responses

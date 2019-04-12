from collections import defaultdict
from multiprocessing.pool import Pool

import cython
from traceutils.progress.bar import Progress
from traceutils.radix.ip2as cimport IP2AS
from traceutils.scamper.hop cimport Trace
from traceutils.scamper.warts cimport WartsReader


@cython.boundscheck(False)
cdef bint are_adjacent(bytes b1, bytes b2):
    cdef int i = 0
    for i in range(len(b1) - 1):
        if b1[i] != b2[i]:
            return False
    i += 1
    return abs(b1[i] - b2[i]) == 1


@cython.boundscheck(False)
cdef char valid_pair(bytes b1, bytes b2):
    cdef char r1 = b1[len(b1) - 1] % 4
    cdef char r2 = b2[len(b2) - 1] % 4
    if r1 == 0:
        if r2 == 1:
            return 2
        return 0
    elif r1 == 1:
        if r2 == 0:
            return -2
        return 4
    elif r1 == 2:
        if r2 == 1:
            return -4
        return 2
    else:
        if r2 == 2:
            return -2
        return 0


cdef class WartsFile:
    def __init__(self, filename, monitor):
        self.filename = filename
        self.monitor = monitor


cdef class VRFinder:

    def __init__(self, IP2AS ip2as):
        self.ip2as = ip2as

    def candidates_parallel(self, list filenames, int poolsize=2):
        cdef set twos = set()
        cdef set fours = set()
        cdef set newtwos, newfours
        pb = Progress(len(filenames), message='Reading traceroutes', callback=lambda: 'Twos {:,d} Fours {:,d}'.format(len(twos), len(fours)))
        with Pool(poolsize) as pool:
            for newtwos, newfours in pb.iterator(pool.imap_unordered(self.candidates, filenames)):
                twos.update(newtwos)
                fours.update(newfours)
        return twos, fours
        
    def candidates_sequential(self, list filenames):
        cdef set twos = set()
        cdef set fours = set()
        cdef str filename
        pb = Progress(len(filenames), message='Reading traceroutes', callback=lambda: 'Twos {:,d} Fours {:,d}'.format(len(twos), len(fours)))
        for filename in pb.iterator(filenames):
            self.candidates(filename, twos=twos, fours=fours)
        return twos, fours

    cpdef tuple candidates(self, str filename, set twos=None, set fours=None):
        cdef WartsReader f
        cdef Trace trace
        cdef list packed
        cdef int i, size
        cdef bytes b1, b2
        cdef tuple pair

        if twos is None:
            twos = set()
        if fours is None:
            fours = defaultdict(set)
        with WartsReader(filename) as f:
            for trace in f:
                trace.prune_dups()
                trace.prune_loops()
                packed = [hop.set_packed() for hop in trace.hops]
                for i in range(len(packed) - 1):
                    b1 = packed[i]
                    if self.ip2as.asn_packed(b1) >= 0:
                        b2 = packed[i+1]
                        if are_adjacent(b1, b2):
                            size = valid_pair(b1, b2)
                            if size != 0:
                                pair = (trace.hops[i].addr, trace.hops[i+1].addr)
                                if size == 2:
                                    twos.add(pair)
                                elif size == 4:
                                    fours.add(pair)
        return twos, fours

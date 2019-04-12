from traceutils.radix.ip2as cimport IP2AS

cdef bint are_adjacent(bytes b1, bytes b2);
cdef char valid_pair(bytes b1, bytes b2);

cdef class WartsFile:
    cdef public str filename, monitor

cdef class VRFinder:
    cdef IP2AS ip2as

    cpdef tuple candidates(self, str filename, set twos=*, set fours=*);

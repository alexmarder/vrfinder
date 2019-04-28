from finder import CandidateInfo


class VerifyInfo:
    def __init__(self):
        self.tps = set()
        self.fps = set()
        self.fns = set()
        self.tns = set()

    @property
    def tp(self):
        return len(self.tps)

    @property
    def tn(self):
        return len(self.tns)

    @property
    def fp(self):
        return len(self.fps)

    @property
    def fn(self):
        return len(self.fns)

    def __repr__(self):
        return 'TP {:,d} TN {:,d} FP {:,d} FN {:,d} PPV {:.2%} Recall {:.2%}'.format(self.tp, self.tn, self.fp, self.fn, self.ppv, self.recall)

    @property
    def ppv(self):
        denom = self.tp + self.fp
        if denom == 0:
            return float('nan')
        return self.tp / denom

    @property
    def recall(self):
        denom = self.tp + self.fn
        if denom == 0:
            return float('nan')
        return self.tp / denom


def validate(alladdrs, candidates: CandidateInfo, valid, vpn, default, ixps, prev):
    vi = VerifyInfo()
    gtaddrs = vpn | default
    addrs = gtaddrs & alladdrs
    for addr in addrs:
        pos = False
        if addr in candidates.twos:
            pos = True
        elif addr in candidates.fours:
            if valid[addr] > 1:
                pos = True
            else:
                pos = False
        elif addr in ixps:
            pos = True
        if addr in vpn:
            if pos:
                vi.tps.add(addr)
            else:
                if any(x in gtaddrs for x in prev[addr]):
                    vi.fns.add(addr)
        else:
            if pos:
                vi.fps.add(addr)
            else:
                vi.tns.add(addr)
    return vi

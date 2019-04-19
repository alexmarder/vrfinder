from collections import defaultdict
from multiprocessing.pool import Pool

from traceutils.progress.bar import Progress
from traceutils.scamper.warts import WartsReader
from traceutils.utils.net import prefix_addrs


def read_responses(filename):
    responses = defaultdict(bool)
    with WartsReader(filename) as f:
        for ping in f:
            resp = any(r.icmp_type == 0 for r in ping.responses)
            responses[ping.dst] |= resp
    return responses


class PingTest:

    def __init__(self, files):
        self.files = files
        self._responses = defaultdict(bool)
        self.responses = {}

    def read_responses_all(self, poolsize=35):
        pb = Progress(len(self.files), 'Reading pings', callback=lambda: 'Responses {:,d}'.format(sum(self.responses.values())))
        with Pool(poolsize) as pool:
            for responses in pb.iterator(pool.imap_unordered(read_responses, self.files)):
                for a, b in responses.items():
                    self._responses[a] |= b
        self.responses = dict(self._responses)
            # for file in pb.iterator(self.files):
            #     self.read_responses(file)

    def read_responses(self, filename):
        responses = defaultdict(bool)
        with WartsReader(filename) as f:
            for ping in f:
                resp = any(r.icmp_type == 0 for r in ping.responses)
                responses[ping.dst] |= resp
        return responses

    def test_candidates(self, candidates):
        valid = {}
        for a in candidates:
            w, x, y, z = prefix_addrs(a, 2)
            if self._responses[w] or self._responses[z]:
                valid[a] = 1
                continue
            if self._responses[x] and self._responses[y]:
                valid[a] = 2
                continue
            if self._responses[a]:
                valid[a] = 3
                continue
            else:
                valid[a] = 4
        return valid

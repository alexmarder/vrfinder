from collections import defaultdict

from traceutils.progress.bar import Progress
from traceutils.scamper.warts import WartsReader
from traceutils.utils.net import prefix_addrs


class PingTest:

    def __init__(self, files):
        self.files = files
        self.responses = defaultdict(bool)

    def read_responses_all(self):
        pb = Progress(len(self.files), 'Reading pings', callback=lambda: 'Responses {:,d}'.format(sum(self.responses.values())))
        for file in pb.iterator(self.files):
            self.read_responses(file)

    def read_responses(self, filename):
        with WartsReader(filename) as f:
            for ping in f:
                resp = any(r.icmp_type == 0 for r in ping.responses)
                self.responses[ping.dst] |= resp

    def test_candidates(self, candidates):
        valid = {}
        for a in candidates:
            w, x, y, z = prefix_addrs(a, 2)
            if self.responses[w] or self.responses[z]:
                valid[a] = 1
                continue
            if self.responses[x] and self.responses[y]:
                valid[a] = 2
                continue
            if self.responses[a]:
                valid[a] = 3
                continue
            else:
                valid[a] = 4
        return valid

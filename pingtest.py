from collections import defaultdict
from multiprocessing.pool import Pool

from traceutils.progress.bar import Progress
from traceutils.scamper.hop import ICMPType
from traceutils.scamper.warts import WartsReader
from traceutils.utils.net import prefix_addrs


def read_responses(filename):
    responses = defaultdict(bool)
    with WartsReader(filename) as f:
        for ping in f:
            resp = any(r.type == ICMPType.echo_reply for r in ping.responses)
            responses[ping.dst] |= resp
    return responses


class PingTest:

    def __init__(self, files):
        self.files = files
        self._responses = defaultdict(bool)
        self.responses = {}

    def read_responses_all(self, poolsize=25):
        pb = Progress(len(self.files), 'Reading pings', callback=lambda: 'Responses {:,d}'.format(sum(self._responses.values())))
        with Pool(poolsize) as pool:
            for responses in pb.iterator(pool.imap_unordered(read_responses, self.files)):
                for a, b in responses.items():
                    self._responses[a] |= b
        self.responses = dict(self._responses)
            # for file in pb.iterator(self.files):
            #     self.read_responses(file)
    # 
    # def read_responses(self, filename):
    #     responses = defaultdict(bool)
    #     with WartsReader(filename) as f:
    #         for ping in f:
    #             resp = any(r.type == ICMPType.echo_reply for r in ping.responses)
    #             responses[ping.dst] |= resp
    #     return responses

    def test_candidates(self, candidates):
        valid = {}
        for a in candidates:
            # if a not in self.responses:
            #     valid[a] = 6
            #     continue
            w, x, y, z = prefix_addrs(a, 2)
            if w not in self.responses and x not in self.responses and y not in self.responses and z not in self.responses:
                valid[a] = 6
                continue
            b = y if x == a else y
            # if self.responses[w] or self.responses[z]:
            if self.responses.get(w, False) or self.responses.get(z, False):
                valid[a] = 1
                continue
            if self.responses.get(x, False) and self.responses.get(y, False):
                valid[a] = 2
                continue
            if self.responses.get(a, False):
                valid[a] = 3
                continue
            if self.responses.get(b, False):
                valid[a] = 5
                continue
            else:
                valid[a] = 4
        return valid

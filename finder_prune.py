from collections import defaultdict

from finder_info import FinderInfo


class FinderPrune(FinderInfo):

    def __init__(self):
        super().__init__()

    def tripprev(self):
        prev = defaultdict(set)
        for w, x, y in self.triplets:
            prev[x].add(w)
        return prev

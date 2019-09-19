from abc import ABC, abstractmethod


class AbstractInfo(ABC):

    def __init__(self):
        super().__init__()
        self.twos = set()
        self.fours = set()

    def update(self, info):
        for key in vars(info):
            getattr(self, key).update()

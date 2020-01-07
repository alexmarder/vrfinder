import pickle
from collections import UserDict
from typing import Dict, Any

from candidate_info import CandidateInfo


class CandidateContainer(UserDict):
    def __init__(self, data, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.data: Dict[str, CandidateInfo] = data

    def dumps(self):
        return {k: v.dumps() for k, v in self.data.items()}

    def dump(self, file):
        data = self.dumps()
        with open(file, 'wb') as f:
            pickle.dump(data, f)

    @classmethod
    def load(cls, file):
        with open(file, 'rb') as f:
            data: Dict[str, Dict[str, Any]] = pickle.load(f)
        data = {k: CandidateInfo.loads(v) for k, v in data.items()}
        return cls(data)

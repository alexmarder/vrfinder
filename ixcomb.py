import json


class IXComb:
    def __init__(self, filename):
        self.filename = filename
        self.prefixes = {}
        with open(filename) as f:
            for line in f:
                if line[0] != '#':
                    j = json.loads(line)
                    for prefixes in j['prefixes'].values():
                        for prefix in prefixes:
                            self.prefixes[prefix] = j['ix_id']

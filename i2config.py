#!/usr/bin/env python
from argparse import ArgumentParser
from typing import TextIO


class Parser:
    def __init__(self, filename):
        with open(filename) as f:
            self._lines = f.readlines()
        self.lines = iter(self._lines)

    def parse(self):
        d = {}
        while True:
            try:
                line = next(self.lines)
            except StopIteration:
                break
            if not line:
                continue
            line = line.strip()
            if line[0] == '#' or line[0] == '<':
                continue
            if line == '}':
                break
            if '[' in line:
                key, _, value = line.partition('[')
                key = key.strip()
                value = value[:-2]
                value = value.split()
            else:
                key, _, value = line.rpartition(' ')
            if value == '{':
                d[key] = self.parse()
            elif key:
                if isinstance(value, str):
                    value = value[:-1]
                if key in d:
                    d[key] = [d[key], value]
                else:
                    d[key] = value
            else:
                d[value] = True
        return d


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('file')
    args = parser.parse_args()

    with open(args.file) as f:
        parser = Parser(args.file)
        output = parser.parse()
    print(output)

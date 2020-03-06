import re


def extract_regex(filename):
    regexes = {}
    with open(filename) as f:
        for line in f:
            domain, regex, *_ = line.split()
            regexes[domain[:-1]] = re.compile(regex)
    return regexes

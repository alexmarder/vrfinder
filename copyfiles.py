#!/usr/bin/env python
from argparse import ArgumentParser
from datetime import timedelta
from glob import glob
from multiprocessing.pool import Pool
from os import makedirs
from shutil import copy2

from dateutil.parser import parse
from traceutils.progress import Progress

directory = '.'

def copyfile(infile):
    return copy2(infile, directory)

def main():
    global directory
    parser = ArgumentParser()
    parser.add_argument('-b', '--begin', help='Beginning date.', required=True)
    parser.add_argument('-e', '--end', help='Ending date.')
    parser.add_argument('-i', '--interval', type=int, default=1, help='Interval in days')
    parser.add_argument('-n', '--processes', type=int, default=5, help='Number of processes to use.')
    parser.add_argument('-d', '--dir', required=True, help='Output directory for the traceroute files.')
    parser.add_argument('-o', '--output', required=True)
    args = parser.parse_args()
    if not args.end:
        args.end = args.begin
    begin = parse(args.begin)
    end = parse(args.end)
    interval = args.interval
    days = [begin + timedelta(i) for i in range(0, (end - begin).days + 1, interval)]
    if args.dir != '.' and args.dir != '..':
        makedirs(args.dir, exist_ok=True)
    directory = args.dir
    files = []
    for day in days:
        pattern = '/data/topology/ark/data/team-probing/list-7.allpref24/team-1/daily/{year}/cycle-{year}{month:02d}{day:02d}/*.warts.gz'.format(year=day.year, month=day.month, day=day.day)
        files.extend(glob(pattern))
    pb = Progress(len(files), 'Copying files')
    with Pool(args.processes) as pool, open(args.output, 'w') as f:
        for outfile in pb.iterator(pool.imap_unordered(copyfile, files)):
            f.write('{}\n'.format(outfile))

if __name__ == '__main__':
    main()

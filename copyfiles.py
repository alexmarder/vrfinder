#!/usr/bin/env python
import os
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
    filename = os.path.join(directory, os.path.basename(infile))
    if not os.path.exists(filename):
        return copy2(infile, directory), True
    return filename, False

def datefiles(args):
    files = []
    if not args.end:
        args.end = args.begin
    begin = parse(args.begin)
    end = parse(args.end)
    interval = args.interval
    days = [begin + timedelta(i) for i in range(0, (end - begin).days + 1, interval)]
    for day in days:
        pattern = '/data/topology/ark/data/team-probing/list-7.allpref24/team-1/daily/{year}/cycle-{year}{month:02d}{day:02d}/*.warts.gz'.format(year=day.year, month=day.month, day=day.day)
        files.extend(glob(pattern))
    return files

def filelist(args):
    with open(args.file) as f:
        files = [line.strip() for line in f]
    return files

def main():
    global directory
    parser = ArgumentParser()
    parser.add_argument('-n', '--processes', type=int, default=5, help='Number of processes to use.')
    parser.add_argument('-d', '--dir', required=True, help='Output directory for the traceroute files.')
    parser.add_argument('-o', '--output', required=True)
    subparsers = parser.add_subparsers()

    date = subparsers.add_parser('date')
    date.add_argument('-b', '--begin', help='Beginning date.', required=True)
    date.add_argument('-e', '--end', help='Ending date.')
    date.add_argument('-i', '--interval', type=int, default=1, help='Interval in days')
    date.set_defaults(func=datefiles)

    flist = subparsers.add_parser('file')
    flist.add_argument('-f', '--file', required=True, help='File containing files to be copied.')
    flist.set_defaults(func=filelist)

    args = parser.parse_args()
    files = args.func(args)
    if args.dir != '.' and args.dir != '..':
        makedirs(args.dir, exist_ok=True)
    directory = args.dir
    copied = 0
    skipped = 0
    pb = Progress(len(files), 'Copying files', callback=lambda: 'Copied {:,d} Skipped {:,d}'.format(copied, skipped))
    with Pool(args.processes) as pool, open(args.output, 'w') as f:
        for outfile, b in pb.iterator(pool.imap_unordered(copyfile, files)):
            if b:
                copied += 1
            else:
                skipped += 1
            f.write('{}\n'.format(outfile))

if __name__ == '__main__':
    main()

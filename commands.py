def arksyncf(vps):
    return ','.join(sorted(vps))


def shmuxf(vps):
    return ' '.join(sorted(vps))


def command(infile, outfile, ctype, bz2=False, batch=True, nowait=True, vps=None):
    scamper = '/usr/local/ark/pkg/scamper-cvs-20181025/bin/scamper'
    if ctype == 'ping':
        scom = 'ping -c 2 -o 1'
    elif ctype == 'trace':
        scom = 'trace -w 1 -P icmp-paris'
    else:
        raise Exception('Invalid command type: {}'.format(ctype))
    directory = '/usr/local/ark/activity/vrfinder/'
    infile = '{}{}'.format(directory, infile)
    outfile = '{}{}'.format(directory, outfile)
    out = '-' if bz2 else outfile
    com = "shmux -c '{} -o {} -O warts -p 100 -c \"{}\" -f {}".format(scamper, out, scom, infile)
    com += ' {}> /dev/null'.format(2 if bz2 else '&')
    if bz2:
        com += ' | bzip2 > {}'.format(outfile)
    if nowait:
        com += ' &'
    com += "'"
    if batch:
        com += ' -B'
    if vps:
        com += ' {}'.format(' '.join(vps))
    return com

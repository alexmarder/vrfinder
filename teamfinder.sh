#!/usr/bin/env bash
./finder.py -f files/201104.files -I /data/external/peeringdb-dumps/v1/2011/04/peeringdb_dump_2011_04_30.sqlite -p 25 -o infos/team/201104.rttls.pickle
./finder.py -f files/201110.files -I /data/external/peeringdb-dumps/v1/2011/10/peeringdb_dump_2011_10_30.sqlite -p 25 -o infos/team/201110.rttls.pickle
./finder.py -f files/201207.files -I /data/external/peeringdb-dumps/v1/2012/07/peeringdb_dump_2012_07_30.sqlite -p 25 -o infos/team/201207.rttls.pickle
./finder.py -f files/201304.files -I /data/external/peeringdb-dumps/v1/2013/04/peeringdb_dump_2013_04_30.sqlite -p 25 -o infos/team/201304.rttls.pickle
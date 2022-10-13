#!/bin/python
# Utility to convert from the csv format to metalsoft port-group json format
# sample input csv:
# VirtualPortGroup,PhysicalGroup,SPA Port,SPB Port,SPA Port,SPB Port,
# VG1,PG1,spa_ocp_0_eth0,spb_ocp_0_eth0,spa_iom_0_eth2,spb_iom_0_eth2,
# VG2,PG2,spa_ocp_0_eth1,spb_ocp_0_eth1,spa_iom_0_eth3,spb_iom_0_eth3,
# VG3,PG3,spa_iom_0_eth0,spb_iom_0_eth0,spa_iom_1_eth2,spb_iom_1_eth2,
# VG4,PG4,spa_iom_0_eth1,spb_iom_0_eth1,spa_iom_1_eth3,spb_iom_1_eth3,
# VG5,PG5,spa_iom_1_eth0,spb_iom_1_eth0,spa_ocp_0_eth2,spb_ocp_0_eth2, 

#output file in the format:
# {
#     "PG1": [
#         "spa_iom_0_eth0",
#         "spa_iom_0_eth1",
#         "spb_iom_0_eth0",
#         "spb_iom_0_eth1"
#     ],
# ...
# }


import csv
import sys
import json
from collections import OrderedDict


if len(sys.argv)!=4:
    sys.stderr.write("Syntax: {} <pg_csv_file.csv> <metalsoft_pg.json> <metalsoft_pg_order.json>\n".format(sys.argv[0]))
    sys.exit(1)

pg_csv_file_path =sys.argv[1]
pg_json_file_path =sys.argv[2]
pg_order_json_file_path =sys.argv[3]

pgs=OrderedDict()
with open(pg_csv_file_path) as csvfile:
    csvreader = csv.reader(csvfile)
    next(csvreader)

    for row in csvreader:
        pgs[row[0]] = [
            row[2],
            row[3],
            row[4],
            row[5]
        ]
#print(pgs)
with open(pg_json_file_path, 'w') as outfile:
    json.dump(pgs, outfile, indent=4)

with open(pg_order_json_file_path, 'w') as outfile:
    json.dump(pgs.keys(), outfile, indent=4)

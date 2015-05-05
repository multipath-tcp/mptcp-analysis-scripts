#! /usr/bin/python3
# -*- coding: utf-8 -*-
#
#  Copyright 2014-2015 Matthieu Baerts & Quentin De Coninck
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.

# ./extract_subnet_from_file.py file IP_VERSION CIDR
#
# e.g.: ./extract_subnet_from_file.py mptcp_org_ipv4.txt 4 24
# mptcp_org_ipv4.txt contains a Python printed list of IP addresses on 1st line:
#  ['1.1.1.1', '2.2.2.2']

import sys

# Get args
if len(sys.argv) < 3:
    print("Not enough args: ./extract_subnet_from_file.py file CIDR")
    sys.exit(1)

file = sys.argv[1]
prefix = sys.argv[2]
try:
    prefix = int(prefix)
except:
    print("IP prefix (CIDR) is not a number, exit")
    sys.exit(1)

# Get IPs
with open(file) as f:
    line = f.readlines()[0]

IPs = line[2:-2].replace("', '", ' ').split()
IPs_set = set()

# Detect IP version
v4 = '.' in IPs[0]
if v4:
    blocks = prefix / 8
    sep = '.'
else:
    blocks = prefix / 16
    sep = ':'

# Add to set
for ip in IPs:
    start_char = ip.find(sep)
    i = blocks
    while start_char >= 0 and i > 1:
        start_char = ip.find(sep, start_char + 1)
        i -= 1
    IPs_set.add(ip[:start_char])

print("Nb of IPs: " + str(len(IPs)))
print("Nb of IPs prefix " + str(prefix) + ": " + str(len(IPs_set)))

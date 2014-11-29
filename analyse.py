#! /usr/bin/python3
# -*- coding: utf-8 -*-
#
#  Copyright 2014 Matthieu Baerts & Quentin De Coninck
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
#
# ./analyse.py
#
# To install on this machine: gnuplot, gnuplot.py

# TODO the script starts with the assumption that one file is provided, but it
# has to be generalized to cope with multiple files

# TODO must manage the case where the pcap file is from a TCP connection

##################################################
##                  CONSTANTS                   ##
##################################################
DEF_OUT_DIR = 'traces'

##################################################
##                   IMPORTS                    ##
##################################################
import glob
import os
import subprocess
import sys

##################################################
##                 PREPROCESSING                ##
##################################################
out_dir_exp = os.path.expanduser(DEF_OUT_DIR)

if len(sys.argv) < 2:
    print("You have to give at least one argument to run this script")
    exit(1)

file = sys.argv[1]

# Files from UI tests will be compressed; unzip them
if file.endswith('.gz'):
    print("Uncompressing " + file + " to " + out_dir_exp)
    output = open(out_dir_exp + '/' + file[:-3], 'w')
    cmd = 'gunzip -c -9 ' + file
    print(cmd)
    if subprocess.call(cmd.split(), stdout=output) != 0:
        print("Error when uncompressing " + file)
    output.close()
elif file.endswith('.pcap'):
    # Move the file to out_dir_exp
    print("Moving " + file + " to " + out_dir_exp)
    cmd = 'mv ' + file + " " + out_dir_exp + "/"
    if subprocess.call(cmd.split()) != 0:
        print("Error when moving " + file)
else:
    print(file + ": not in a valid format")
    exit(1)


##################################################
##                  MPTCPTRACE                  ##
##################################################

# If file is a .pcap, use it for mptcptrace
for pcap_file in glob.glob(os.path.join(out_dir_exp, '*.pcap')):
    cmd = 'mptcptrace -f ' + pcap_file + ' -s -w 2'
    if subprocess.call(cmd.split()) != 0:
        print("Error of mptcptrace with " + pcap_file)

    # The mptcptrace call will generate .csv files to cope with
    for csv_file in glob.glob('*.pcap'):
        #TODO
        pass

#! /usr/bin/python
# -*- coding: utf-8 -*-
#
#  Copyright 2015 Matthieu Baerts & Quentin De Coninck
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
#  To install on this machine: matplotlib, numpy

from __future__ import print_function

##################################################
##                   IMPORTS                    ##
##################################################

import argparse
import common as co
import glob
import matplotlib
# Do not use any X11 backend
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import mptcp
import numpy as np
import os
import os.path
import pickle
import sys
import tcp

##################################################
##                  ARGUMENTS                   ##
##################################################

parser = argparse.ArgumentParser(
    description="Summarize sequence number together in one graph")
parser.add_argument("-s",
                    "--stat", help="directory where the stat files are stored", default=co.DEF_STAT_DIR+'_'+co.DEF_IFACE)
parser.add_argument('-S',
                    "--sums", help="directory where the summary graphs will be stored", default=co.DEF_SUMS_DIR+'_'+co.DEF_IFACE)
parser.add_argument("-d",
                    "--dirs", help="list of directories to aggregate", nargs="+")
parser.add_argument("-c",
                    "--csv", help="take a list of csv files", nargs="+")

args = parser.parse_args()

stat_dir_exp = os.path.abspath(os.path.expanduser(args.stat))
sums_dir_exp = os.path.abspath(os.path.expanduser(args.sums))
csv_dir_exp = os.path.abspath(os.path.expanduser(args.csv))

co.check_directory_exists(sums_dir_exp)

def check_in_list(dirpath, dirs):
    """ Check if dirpath is one of the dir in dirs, True if dirs is empty """
    if not dirs:
        return True
    return os.path.basename(dirpath) in dirs


def fetch_data(dir_exp):
    co.check_directory_exists(dir_exp)
    dico = {}
    for dirpath, dirnames, filenames in os.walk(dir_exp):
        if check_in_list(dirpath, args.dirs):
            for fname in filenames:
                try:
                    stat_file = open(os.path.join(dirpath, fname), 'r')
                    dico[fname] = pickle.load(stat_file)
                    stat_file.close()
                except IOError as e:
                    print(str(e) + ': skip stat file ' + fname, file=sys.stderr)
    return dico

connections = fetch_data(stat_dir_exp)

def collect_seq():
    seqs = {}
    for csv_path in glob.glob(os.path.join(csv_dir_exp, '*.csv')):
        csv_fname = os.path.basename(csv_path)
        try:
            csv_file = open(csv_path)
            data = csv_file.readlines()
            csv_file.close()
        except IOError as e:
            print(str(e))
            continue

        seqs_csv = []

        for line in data:
            split_line = line.split(',')
            if len(split_line) == 6:
                if int(split_line[3]) == 0:
                    # ACK
                    timestamp = float(split_line[0])
                    seq_ack = int(split_line[1])
                    flow_id = int(split_line[2]) - 1
                    # is_ack = True # int(split_line[3]) == 0
                    # dummy = int(split_line[4])
                    # dummy_2 = int(split_line[5])
                    seqs_csv.append((timestamp, seq_ack, flow_id))

                elif int(split_line[3]) == 1:
                    # MAP
                    timestamp = float(split_line[0])
                    seq_start = int(split_line[1])
                    flow_id = int(split_line[2]) - 1
                    # is_ack = False # int(split_line[3]) == 1
                    seq_end = int(split_line[4])
                    reinject_flow = int(split_line[5]) - 1 # If not negative, the flow where packet was first seen
                    seqs_csv.append((timestamp, seq_start, flow_id, seq_end, reinject_flow))

        seqs[csv_fname] = seqs_csv

    return seqs
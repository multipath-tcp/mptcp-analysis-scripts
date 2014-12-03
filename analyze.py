#! /usr/bin/python
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
# ./analyze.py [input_dir [traces_dir [graphs_dir]]]
#
# To install on this machine: gnuplot, gnuplot.py, numpy, mptcptrace, tcptrace,
# xpl2gpl

# TODO must manage the case where the pcap file is from a TCP connection
# (differency them)
from __future__ import print_function

##################################################
##                   IMPORTS                    ##
##################################################
from numpy import *

import glob
import Gnuplot
import os
import os.path
import subprocess
import sys

class cd:
    """Context manager for changing the current working directory"""
    def __init__(self, newPath):
        self.newPath = newPath

    def __enter__(self):
        self.savedPath = os.getcwd()
        os.chdir(self.newPath)

    def __exit__(self, etype, value, traceback):
        os.chdir(self.savedPath)

##################################################
##                  CONSTANTS                   ##
##################################################
DEF_IN_DIR = 'input'
DEF_TRACE_DIR = 'traces'
DEF_GRAPH_DIR = 'graphs'

##################################################
##                   ARGUMENTS                  ##
##################################################

if len(sys.argv) >= 2:
    in_dir = sys.argv[1]
else:
    in_dir = DEF_IN_DIR

if len(sys.argv) >= 3:
    trace_dir = sys.argv[2]
else:
    trace_dir = DEF_TRACE_DIR

if len(sys.argv) >= 4:
    graph_dir = sys.argv[3]
else:
    graph_dir = DEF_GRAPH_DIR

in_dir_exp = os.path.expanduser(in_dir)
trace_dir_exp = os.path.expanduser(trace_dir)
graph_dir_exp = os.path.expanduser(graph_dir)

##################################################
##                 PREPROCESSING                ##
##################################################

for dirpath, dirnames, filenames in os.walk(os.path.join(os.getcwd(), in_dir_exp)):
    for file in filenames:
        # Files from UI tests will be compressed; unzip them
        if file.endswith('.gz'):
            print("Uncompressing " + file + " to " + trace_dir_exp)
            output = open(trace_dir_exp + '/' + file[:-3], 'w')
            cmd = 'gunzip -k -c -9 ' + in_dir_exp + '/' + file
            print(cmd)
            if subprocess.call(cmd.split(), stdout=output) != 0:
                print("Error when uncompressing " + file)
            output.close()
        elif file.endswith('.pcap'):
            # Move the file to out_dir_exp
            print("Copying " + file + " to " + trace_dir_exp)
            cmd = 'cp ' + in_dir_exp + '/' + file + " " + trace_dir_exp + "/"
            if subprocess.call(cmd.split()) != 0:
                print("Error when moving " + file)
        else:
            print(file + ": not in a valid format, skipped")
            continue

##################################################
##                 (MP)TCPTRACE                 ##
##################################################
g = Gnuplot.Gnuplot(debug=0)

def write_graph_csv(csv_file, begin_time, begin_seq):
    """ Write in the graphs directory a new csv file containing relative values
        for plotting them
        Exit the program if an IOError is raised
    """
    try:
        graph_filename = os.path.join(graph_dir_exp, csv_file)
        graph_file = open(graph_filename, 'w')
        # Modify lines for that
        for line in data:
            split_line = line.split(',')
            time = float(split_line[0]) - begin_time
            seq = int(split_line[1]) - begin_seq
            graph_file.write(str(time) + ',' + str(seq) + '\n')
        graph_file.close()
    except IOError as e:
        print('IOError for graph file with ' + csv_file + ': stop')
        exit(1)

def get_begin_values(first_line):
    split_line = first_line.split(',')
    return float(split_line[0]), int(split_line[1])

def create_graph_csv(pcap_file, csv_file):
    """ Generate pdf for the csv file of the pcap file
    """
    in_file = open(csv_file)
    data = in_file.readlines()
    # If file was generated, the csv is not empty
    data_split = map(lambda x: x.split(','), data)
    data_plot = map(lambda x: map(lambda y: float(y), x), data_split)

    g.title(csv_file)
    g('set style data linespoints')
    g.xlabel('Time [s]')
    g.ylabel('Sequence number')
    g.plot(data_plot)
    pdf_filename = os.path.join(graph_dir_exp, \
        pcap_file[len(trace_dir_exp)+1:-5] + "_" + csv_file[:-4] + '.pdf')
    g.hardcopy(filename=pdf_filename, terminal='pdf')
    g.reset()

def process_mptcp_trace(pcap_file):
    """ Process a mptcp pcap file and generate graphs of its subflows """
    cmd = 'mptcptrace -f ' + pcap_file + ' -s -w 2'
    if subprocess.call(cmd.split()) != 0:
        print("Error of mptcptrace with " + pcap_file)

    # The mptcptrace call will generate .csv files to cope with
    for csv_file in glob.glob('*.csv'):
        try:
            in_file = open(csv_file)
            data = in_file.readlines()
            # Check if there is data in file (and not only one line of 0s)
            if not data == [] and len(data) > 1:
                # Collect begin time and seq num to plot graph starting at 0
                begin_time, begin_seq = get_begin_values(data[0])
                write_graph_csv(csv_file, begin_time, begin_seq)

            in_file.close()
            # Remove the csv file
            os.remove(csv_file)

        except IOError as e:
            print('IOError for ' + csv_file + ': skipped')
            continue
        except ValueError as e:
            print('ValueError for ' + csv_file + ': skipped')
            continue

    with cd(graph_dir_exp):
        for csv_file in glob.glob('*.csv'):
            create_graph_csv(pcap_file, csv_file)
            # Remove the csv file
            os.remove(csv_file)

# If file is a .pcap, use it for mptcptrace
for pcap_file in glob.glob(os.path.join(trace_dir_exp, '*.pcap')):
    if pcap_file.startswith('mptcp'):
        process_mptcp_trace(pcap_file)


    print('End for file ' + pcap_file)
    os.remove(pcap_file)

print('End of analyze')

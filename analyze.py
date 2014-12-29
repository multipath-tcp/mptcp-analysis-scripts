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
# analyze.py [-h] [-input INPUT] [-trace TRACE] [-graph GRAPH] [--pcap PCAP]
# Details when running analyze.py -h
#
# To install on this machine: gnuplot, gnuplot.py, numpy, mptcptrace, tcptrace,
# xpl2gpl

from __future__ import print_function

##################################################
##                   IMPORTS                    ##
##################################################

from numpy import *

import argparse
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

in_dir = DEF_IN_DIR
trace_dir = DEF_TRACE_DIR
graph_dir = DEF_GRAPH_DIR
pcap_contains = ""

parser = argparse.ArgumentParser(
    description="Analyze pcap files of TCP or MPTCP connections")
parser.add_argument(
    "-input", help="input directory of the (possibly compressed) pcap files")
parser.add_argument("-trace", help="temporary directory that will be used to store uncompressed "
                    + "pcap files")
parser.add_argument(
    "-graph", help="directory where the graphs of the pcap files will be stored")
parser.add_argument(
    "--pcap", help="analyze only pcap files containing the given string")
parser.add_argument("--keep", help="keep the original file with -k option of gunzip, if it exists",
                    action="store_true")
parser.add_argument(
    "--clean", help="remove noisy traffic on lo", action="store_true")
args = parser.parse_args()

if args.input:
    in_dir = args.input

if args.trace:
    trace_dir = args.trace

if args.graph:
    graph_dir = args.graph

if args.pcap:
    pcap_contains = args.pcap

in_dir_exp = os.path.expanduser(in_dir)
trace_dir_exp = os.path.expanduser(trace_dir)
graph_dir_exp = os.path.expanduser(graph_dir)

##################################################
##                 PREPROCESSING                ##
##################################################


def check_directory_exists(directory):
    """ Check if the directory exists, and create it if needed
        If directory is a file, exit the program
    """
    if os.path.exists(directory):
        if not os.path.isdir(directory):
            print(directory + " is a file: stop")
    else:
        os.makedirs(directory)

check_directory_exists(trace_dir_exp)
for dirpath, dirnames, filenames in os.walk(os.path.join(os.getcwd(), in_dir_exp)):
    for file in filenames:
        if pcap_contains in file:
            # Files from UI tests will be compressed; unzip them
            if file.endswith('.gz'):
                print("Uncompressing " + file + " to " + trace_dir_exp)
                output = open(os.path.join(trace_dir_exp, file[:-3]), 'w')
                if args.keep:
                    cmd = 'gunzip -k -c -9 ' + os.path.join(dirpath, file)
                else:
                    cmd = 'gunzip -c -9 ' + os.path.join(dirpath, file)
                if subprocess.call(cmd.split(), stdout=output) != 0:
                    print("Error when uncompressing " + file)
                output.close()
            elif file.endswith('.pcap'):
                # Move the file to out_dir_exp
                print("Copying " + file + " to " + trace_dir_exp)
                cmd = 'cp ' + \
                    os.path.join(dirpath, file) + " " + trace_dir_exp + "/"
                if subprocess.call(cmd.split()) != 0:
                    print("Error when moving " + file)
            else:
                print(file + ": not in a valid format, skipped")
                continue


def clean_loopback_pcap(pcap_fname):
    """ Remove noisy traffic (port 1984), see netstat """
    tmp_pcap = "tmp.pcap"
    cmd = 'tshark -Y !(tcp.dstport==1984||tcp.srcport==1984) -r ' + pcap_fname \
        + ' -w ' + tmp_pcap + ' -F pcap'
    if subprocess.call(cmd.split()) != 0:
        print("Error in cleaning " + pcap_fname)
        return
    cmd = "mv " + tmp_pcap + " " + pcap_fname
    if subprocess.call(cmd.split()) != 0:
        print("Error in moving " + tmp_pcap + " to " + pcap_fname)


##################################################
##                  MPTCPTRACE                  ##
##################################################

g = Gnuplot.Gnuplot(debug=0)


def write_graph_csv(csv_file, data, begin_time, begin_seq):
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


def generate_title(csv_file, connections):
    """ Generate the title for a mptcp connection """
    # Get the id of the mptcp connection (between last _ and last . in the csv
    # filename)
    last_underscore_index = csv_file.rindex("_")
    last_dot_index = csv_file.rindex(".")
    connection_id = csv_file[last_underscore_index + 1:last_dot_index]

    title = "flows:" + str(len(connections[connection_id])) + " "

    # Get flow type (c2s or s2c); if c2s, correct order, otherwise reverse src
    # and dst
    first_underscore_index = csv_file.index("_")
    reverse = (csv_file[0:first_underscore_index] == "s2c")

    # Show all details of the subflows
    for sub_flow_id, data in connections[connection_id].iteritems():
        # \n must be interpreted as a raw type to works with GnuPlot.py
        title += r'\n' + "sf: " + sub_flow_id + " "
        if reverse:
            title += "(" + data['wscaledst'] + " " + data['wscalesrc'] + ") "
            title += data['daddr'] + ":" + data['dport'] + \
                " -> " + data['saddr'] + ":" + data['sport']
        else:
            title += "(" + data['wscalesrc'] + " " + data['wscaledst'] + ") "
            title += data['saddr'] + ":" + data['sport'] + \
                " -> " + data['daddr'] + ":" + data['dport']
    return title


def create_graph_csv(pcap_file, csv_file, connections):
    """ Generate pdf for the csv file of the pcap file
    """
    try:
        in_file = open(csv_file)
        data = in_file.readlines()
    except IOError as e:
        print('IOError for ' + csv_file + ': skipped')
        return

    # If file was generated, the csv is not empty
    data_split = map(lambda x: x.split(','), data)
    data_plot = map(lambda x: map(lambda y: float(y), x), data_split)

    g('set title "' + generate_title(csv_file, connections) + '"')
    g('set style data linespoints')
    g.xlabel('Time [s]')
    g.ylabel('Sequence number')
    g.plot(data_plot)
    pdf_filename = os.path.join(graph_dir_exp,
                                pcap_file[len(trace_dir_exp) + 1:-5] + "_" + csv_file[:-4] + '.pdf')
    g.hardcopy(filename=pdf_filename, terminal='pdf')
    g.reset()


def extract_flow_data(out_file):
    """ Given an (open) file, return a dictionary of as many elements as there are flows """
    # Return at the beginning of the file
    out_file.seek(0)
    data = out_file.readlines()
    connections = {}
    current_connection = False
    for line in data:
        # Case 1: line start with MPTCP connection
        if line.startswith("MPTCP connection"):
            # A typical line: MPTCP connection 0 with id 2
            words = line.split()
            current_connection = words[-1]
            connections[current_connection] = {}

        # Case 2: line for a subflow
        elif current_connection is not False and line.startswith("\tSubflow"):
            # A typical line:
            #   Subflow 0 with wscale : 6 0 IPv4 sport 59570 dport 443 saddr
            # 37.185.171.74 daddr 194.78.99.114
            words = line.split()
            sub_flow_id = words[1]
            connections[current_connection][sub_flow_id] = {}
            index_wscale = words.index("wscale")
            connections[current_connection][sub_flow_id][
                'wscalesrc'] = words[index_wscale + 2]
            connections[current_connection][sub_flow_id][
                'wscaledst'] = words[index_wscale + 3]
            index = words.index("sport")
            while index + 1 < len(words):
                attr = words[index]
                value = words[index + 1]
                connections[current_connection][sub_flow_id][attr] = value
                index += 2

        # Case 3: skip the line (no more current connection)
        else:
            current_connection = False
    return connections


def process_mptcp_trace(pcap_file):
    """ Process a mptcp pcap file and generate graphs of its subflows """
    cmd = 'mptcptrace -f ' + pcap_file + ' -s -w 2'
    pcap_flow_data = pcap_file[:-5] + '.out'
    flow_data = open(pcap_flow_data, 'w+')
    if subprocess.call(cmd.split(), stdout=flow_data) != 0:
        print("Error of mptcptrace with " + pcap_file + "; skip process")
        return

    connections = extract_flow_data(flow_data)
    # Don't forget to close and remove pcap_flow_data
    flow_data.close()
    os.remove(pcap_flow_data)
    # The mptcptrace call will generate .csv files to cope with
    for csv_file in glob.glob('*.csv'):
        try:
            in_file = open(csv_file)
            data = in_file.readlines()
            # Check if there is data in file (and not only one line of 0s)
            if not data == [] and len(data) > 1:
                # Collect begin time and seq num to plot graph starting at 0
                begin_time, begin_seq = get_begin_values(data[0])
                write_graph_csv(csv_file, data, begin_time, begin_seq)

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
            create_graph_csv(pcap_file, csv_file, connections)
            # Remove the csv file
            os.remove(csv_file)

##################################################
##                   TCPTRACE                   ##
##################################################


def prepare_gpl_file(pcap_file, gpl_filename):
    """ Return a gpl file name of a ready-to-use gpl file or None if an error
        occurs
    """
    try:
        gpl_filename_ok = gpl_filename[:-4] + '_ok.gpl'
        gpl_file = open(gpl_filename, 'r')
        gpl_file_ok = open(gpl_filename_ok, 'w')
        data = gpl_file.readlines()
        # Copy everything but the last 4 lines
        for line in data[:-4]:
            gpl_file_ok.write(line)
        # Give the pdf filename where the graph will be stored
        pdf_filename = os.path.join(graph_dir_exp,
                                    pcap_file[
                                        len(trace_dir_exp) + 1:-5] + "_" + gpl_filename[:-4]
                                    + '.pdf')

        # Needed to give again the line with all data (5th line from the end)
        # Better to reset the plot (to avoid potential bugs)
        to_write = "set output '" + pdf_filename + "'\n" \
            + "set terminal pdf\n" \
            + data[-5] \
            + "set terminal pdf\n" \
            + "set output\n" \
            + "reset\n"
        gpl_file_ok.write(to_write)
        # Don't forget to close files
        gpl_file.close()
        gpl_file_ok.close()
        return gpl_filename_ok
    except IOError as e:
        print('IOError for graph file with ' + gpl_filename + ': skip')
        return None


def process_tcp_trace(pcap_file):
    """ Process a tcp pcap file and generate graphs of its connections """
    # -C for color, -S for sequence numbers, -T for throughput graph
    # -zxy to plot both axes to 0
    # -y to remove some noise in sequence graphs
    cmd = "tcptrace --output_dir=" + os.getcwd() + " --output_prefix=" \
        + pcap_file[:-5] + "_ -C -S -T -zxy -y --noshowzwndprobes --noshowoutorder --noshowrexmit "\
        + "--noshowsacks --noshowzerowindow --noshowurg --noshowdupack3 --noshowzerolensegs " \
        + pcap_file
    if subprocess.call(cmd.split()) != 0:
        print("Error of tcptrace with " + pcap_file + "; skip process")
        return

    # The tcptrace call will generate .xpl files to cope with
    for xpl_file in glob.glob(os.path.join(trace_dir_exp, pcap_file[len(trace_dir_exp) + 1:-5]
                                           + '*.xpl')):
        cmd = "xpl2gpl " + xpl_file
        if subprocess.call(cmd.split()) != 0:
            print("Error of xpl2gpl with " + xpl_file + "; skip xpl file")
            continue
        prefix_file = xpl_file[len(trace_dir_exp) + 1:-4]
        gpl_filename = prefix_file + '.gpl'
        gpl_filename_ok = prepare_gpl_file(pcap_file, gpl_filename)
        if gpl_filename_ok:
            cmd = "gnuplot " + gpl_filename_ok
            if subprocess.call(cmd.split()) != 0:
                print("Error of tcptrace with " + pcap_file + "; skip process")
                return

        # Delete gpl, xpl and others files generated
        try:
            os.remove(gpl_filename)
            os.remove(gpl_filename_ok)
            try:
                os.remove(prefix_file + '.datasets')
            except OSError as e2:
                # Throughput graphs have not .datasets file
                pass
            os.remove(prefix_file + '.labels')
            os.remove(xpl_file)
        except OSError as e:
            print(str(e) + ": skipped")

##################################################
##                     MAIN                     ##
##################################################

check_directory_exists(graph_dir_exp)
# If file is a .pcap, use it for (mp)tcptrace
for pcap_file in glob.glob(os.path.join(trace_dir_exp, '*.pcap')):
    pcap_filename = pcap_file[len(trace_dir_exp) + 1:]
    # Cleaning, if needed (in future pcap, tcpdump should do the job)
    if args.clean:
        clean_loopback_pcap(pcap_file)
    # Prefix of the name determine the protocol used
    if pcap_filename.startswith('mptcp'):
        process_mptcp_trace(pcap_file)
    elif pcap_filename.startswith('tcp'):
        process_tcp_trace(pcap_file)
    else:
        print(pcap_file + ": don't know the protocol used; skipped")

    print('End for file ' + pcap_file)
    os.remove(pcap_file)

print('End of analyze')

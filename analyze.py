#! /usr/bin/python
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
#
# analyze.py [-h] [-input INPUT] [-trace TRACE] [-graph GRAPH] [--pcap PCAP]
# Details when running analyze.py -h
#
# To install on this machine: gnuplot, gnuplot.py, numpy, mptcptrace, tcptrace,
# xpl2gpl, tshark

from __future__ import print_function

##################################################
##                   IMPORTS                    ##
##################################################

from common import *
from numpy import *

import argparse
import glob
import Gnuplot
import os
import os.path
import pickle
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

# The default input directory (with .pcap and .pcap.gz files)
DEF_IN_DIR = 'input'
# The default traces directory (kind of temparary directory, where traces
# will be stored)
DEF_TRACE_DIR = 'traces'
# The default graph directory (output directory for graphes)
DEF_GRAPH_DIR = 'graphs'
# The default stat directory
DEF_STAT_DIR = 'stats'
# IPv4 localhost address
LOCALHOST_IPv4 = '127.0.0.1'
# Port number of RedSocks
PORT_RSOCKS = '8123'
# Prefix of the Wi-Fi interface IP address
PREFIX_WIFI_IF = '192.168.'
# Size of Latin alphabet
SIZE_LAT_ALPH = 26

##################################################
##                   ARGUMENTS                  ##
##################################################

in_dir = DEF_IN_DIR
trace_dir = DEF_TRACE_DIR
graph_dir = DEF_GRAPH_DIR
stat_dir = DEF_STAT_DIR
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
    "-stat", help="directory where the stats of the pcap files will be stored")
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

if args.stat:
    stat_dir = args.stat

if args.pcap:
    pcap_contains = args.pcap

in_dir_exp = os.path.expanduser(in_dir)
trace_dir_exp = os.path.expanduser(trace_dir)
graph_dir_exp = os.path.expanduser(graph_dir)
stat_dir_exp = os.path.expanduser(stat_dir)

##################################################
##                 PREPROCESSING                ##
##################################################

check_directory_exists(trace_dir_exp)
for dirpath, dirnames, filenames in os.walk(os.path.join(os.getcwd(), in_dir_exp)):
    for fname in filenames:
        if pcap_contains in fname:
            # Files from UI tests will be compressed; unzip them
            if fname.endswith('.gz'):
                print("Uncompressing " + fname + " to " + trace_dir_exp)
                output = open(os.path.join(trace_dir_exp, fname[:-3]), 'w')
                if args.keep:
                    cmd = 'gunzip -k -c -9 ' + os.path.join(dirpath, fname)
                else:
                    cmd = 'gunzip -c -9 ' + os.path.join(dirpath, fname)
                if subprocess.call(cmd.split(), stdout=output) != 0:
                    print("Error when uncompressing " + fname)
                output.close()
            elif fname.endswith('.pcap'):
                # Move the file to out_dir_exp
                print("Copying " + fname + " to " + trace_dir_exp)
                cmd = 'cp ' + \
                    os.path.join(dirpath, fname) + " " + trace_dir_exp + "/"
                if subprocess.call(cmd.split()) != 0:
                    print("Error when moving " + fname)
            else:
                print(fname + ": not in a valid format, skipped")
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


def save_connections(pcap_fname, connections):
    """ Using the name pcap_fname, save the statistics about connections """
    stat_fname = os.path.join(
        stat_dir_exp, pcap_fname[len(trace_dir_exp) + 1:-5])
    try:
        stat_file = open(stat_fname, 'w')
        pickle.dump(connections, stat_file)
        stat_file.close()
    except IOError as e:
        print(str(e) + ': no stat file for ' + pcap_fname)

##################################################
##                  MPTCPTRACE                  ##
##################################################

g = Gnuplot.Gnuplot(debug=0)


def get_connection_id(csv_fname):
    """ Given the filename of the csv file, return the id of the MPTCP connection
        The id (returned as str) is assumed to be between last _ and last . in csv_fname
    """
    last_underscore_index = csv_fname.rindex("_")
    last_dot_index = csv_fname.rindex(".")
    return csv_fname[last_underscore_index + 1:last_dot_index]


def is_reverse_connection(csv_fname):
    """ Given the filename of the csv file, return True is it is a c2s flow or False if it is a s2c
        one
        The type is assumed to be before the first _ in csv_fname
    """
    first_underscore_index = csv_fname.index("_")
    return (csv_fname[0:first_underscore_index] == "s2c")


def extract_mptcp_flow_data(out_file):
    """ Given an (open) file, return a dictionary of as many elements as there are mptcp flows """
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
                WSCALESRC] = words[index_wscale + 2]
            connections[current_connection][sub_flow_id][
                WSCALEDST] = words[index_wscale + 3]
            connections[current_connection][sub_flow_id][
                TYPE] = words[index_wscale + 4]
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


def indicates_wifi_or_rmnet(data):
    """ Given data of a mptcp connection subflow, indicates if comes from wifi or rmnet """
    if data[SADDR].startswith(PREFIX_WIFI_IF) or data[DADDR].startswith(PREFIX_WIFI_IF):
        data[IF] = WIFI
    else:
        data[IF] = RMNET


def interesting_mptcp_graph(csv_fname, connections):
    """ Return True if the MPTCP graph is worthy, else False
        This function assumes that a graph is interesting if it has at least one connection that
        if not 127.0.0.1 -> 127.0.0.1
        Note that is the graph is interesting and IPv4, indicates if the traffic is Wi-Fi or rmnet
    """
    connection_id = get_connection_id(csv_fname)
    for sub_flow_id, data in connections[connection_id].iteritems():
        # Only had the case for IPv4, but what is its equivalent in IPv6?
        if not data[TYPE] == 'IPv4':
            return True
        if not (data[SADDR] == LOCALHOST_IPv4 and data[DADDR] == LOCALHOST_IPv4):
            indicates_wifi_or_rmnet(data)
            return True
    return False


def get_begin_values(first_line):
    split_line = first_line.split(',')
    return float(split_line[0]), int(split_line[1])


def write_graph_csv(csv_fname, data, begin_time, begin_seq):
    """ Write in the graphs directory a new csv file containing relative values
        for plotting them
        Exit the program if an IOError is raised
    """
    try:
        graph_fname = os.path.join(graph_dir_exp, csv_fname)
        graph_file = open(graph_fname, 'w')
        # Modify lines for that
        for line in data:
            split_line = line.split(',')
            time = float(split_line[0]) - begin_time
            seq = int(split_line[1]) - begin_seq
            graph_file.write(str(time) + ',' + str(seq) + '\n')
        graph_file.close()
    except IOError as e:
        print('IOError for graph file with ' + csv_fname + ': stop')
        exit(1)


def generate_title(csv_fname, connections):
    """ Generate the title for a mptcp connection """

    connection_id = get_connection_id(csv_fname)
    title = "flows:" + str(len(connections[connection_id])) + " "

    # If not reverse, correct order, otherwise reverse src and dst
    reverse = is_reverse_connection(csv_fname)

    # Show all details of the subflows
    for sub_flow_id, data in connections[connection_id].iteritems():
        # \n must be interpreted as a raw type to works with GnuPlot.py
        title += r'\n' + "sf: " + sub_flow_id + " "
        if reverse:
            title += "(" + data[WSCALEDST] + " " + data[WSCALESRC] + ") "
            title += data[DADDR] + ":" + data[DPORT] + \
                " -> " + data[SADDR] + ":" + data[SPORT]
        else:
            title += "(" + data[WSCALESRC] + " " + data[WSCALEDST] + ") "
            title += data[SADDR] + ":" + data[SPORT] + \
                " -> " + data[DADDR] + ":" + data[DPORT]
        if IF in data:
            title += " [" + data[IF] + "]"
    return title


def create_graph_csv(pcap_fname, csv_fname, connections):
    """ Generate pdf for the csv file of the pcap file
    """
    # First see if useful to show the graph
    if not interesting_mptcp_graph(csv_fname, connections):
        return
    try:
        csv_file = open(csv_fname)
        data = csv_file.readlines()
    except IOError as e:
        print('IOError for ' + csv_fname + ': skipped')
        return

    # If file was generated, the csv is not empty
    data_split = map(lambda x: x.split(','), data)
    data_plot = map(lambda x: map(lambda y: float(y), x), data_split)

    g('set title "' + generate_title(csv_fname, connections) + '"')
    g('set style data linespoints')
    g.xlabel('Time [s]')
    g.ylabel('Sequence number')
    g.plot(data_plot)
    pdf_fname = os.path.join(graph_dir_exp,
                             pcap_fname[len(trace_dir_exp) + 1:-5] + "_" + csv_fname[:-4] + '.pdf')
    g.hardcopy(filename=pdf_fname, terminal='pdf')
    g.reset()


def process_mptcp_trace(pcap_fname):
    """ Process a mptcp pcap file and generate graphs of its subflows """
    cmd = 'mptcptrace -f ' + pcap_fname + ' -s -w 2'
    pcap_flow_data = pcap_fname[:-5] + '.out'
    flow_data_file = open(pcap_flow_data, 'w+')
    if subprocess.call(cmd.split(), stdout=flow_data_file) != 0:
        print("Error of mptcptrace with " + pcap_fname + "; skip process")
        return

    connections = extract_mptcp_flow_data(flow_data_file)
    # Don't forget to close and remove pcap_flow_data
    flow_data_file.close()
    os.remove(pcap_flow_data)

    # The mptcptrace call will generate .csv files to cope with
    for csv_fname in glob.glob('*.csv'):
        try:
            csv_file = open(csv_fname)
            data = csv_file.readlines()
            # Check if there is data in file (and not only one line of 0s)
            if not data == [] and len(data) > 1:
                # Collect begin time and seq num to plot graph starting at 0
                begin_time, begin_seq = get_begin_values(data[0])
                write_graph_csv(csv_fname, data, begin_time, begin_seq)

            csv_file.close()
            # Remove the csv file
            os.remove(csv_fname)

        except IOError as e:
            print('IOError for ' + csv_fname + ': skipped')
            continue
        except ValueError as e:
            print('ValueError for ' + csv_fname + ': skipped')
            continue

    with cd(graph_dir_exp):
        for csv_fname in glob.glob('*.csv'):
            create_graph_csv(pcap_fname, csv_fname, connections)
            # Remove the csv file
            os.remove(csv_fname)

    # Save connections info
    save_connections(pcap_fname, connections)

##################################################
##                   TCPTRACE                   ##
##################################################


def is_number(s):
    """ Check if the str s is a number """
    try:
        float(s)
        return True
    except ValueError:
        return False


def convert_number_to_letter(nb_conn):
    """ Given an integer, return the (nb_conn)th letter of the alphabet (zero-based index) """
    return chr(ord('a') + nb_conn)


def get_prefix_name(nb_conn):
    """ Given an integer, return the (nb_conn)th prefix, based on the alphabet (zero-based index)"""
    if nb_conn >= SIZE_LAT_ALPH:
        mod_nb = nb_conn % SIZE_LAT_ALPH
        div_nb = nb_conn / SIZE_LAT_ALPH
        return get_prefix_name(div_nb - 1) + convert_number_to_letter(mod_nb)
    else:
        return convert_number_to_letter(nb_conn)


def convert_number_to_name(nb_conn):
    """ Given an integer, return a name of type 'a2b', 'aa2ab',... """
    if nb_conn >= (SIZE_LAT_ALPH / 2):
        mod_nb = nb_conn % (SIZE_LAT_ALPH / 2)
        div_nb = nb_conn / (SIZE_LAT_ALPH / 2)
        prefix = get_prefix_name(div_nb - 1)
        return prefix + convert_number_to_letter(2 * mod_nb) + '2' + prefix \
            + convert_number_to_letter(2 * mod_nb + 1)
    else:
        return convert_number_to_letter(2 * nb_conn) + '2' + convert_number_to_letter(2 * nb_conn + 1)


def detect_ipv4(data):
    """ Given the dictionary of a TCP connection, add the type IPv4 if it is an IPv4 connection """
    saddr = data[SADDR]
    daddr = data[DADDR]
    num_saddr = saddr.split('.')
    num_daddr = daddr.split('.')
    if len(num_saddr) == 4 and len(num_daddr) == 4:
        data[TYPE] = 'IPv4'


def extract_tcp_flow_data(out_file):
    """ Given an (open) file, return a dictionary of as many elements as there are tcp flows """
    # Return at the beginning of the file
    out_file.seek(0)
    raw_data = out_file.readlines()
    connections = {}
    # The replacement of whitespaces by nothing prevents possible bugs if we use
    # additional information from tcptrace
    data = map(lambda x: x.replace(" ", ""), raw_data)
    for line in data:
        # Case 1: line start with #; skip it
        if not line.startswith("#"):
            info = line.split(',')
            # Case 2: line is empty or line is the "header line"; skip it
            if len(info) > 1 and is_number(info[0]):
                # Case 3: line begin with number --> extract info
                nb_conn = info[0]
                conn = convert_number_to_name(int(info[0]) - 1)
                connections[conn] = {}
                connections[conn][SADDR] = info[1]
                connections[conn][DADDR] = info[2]
                connections[conn][SPORT] = info[3]
                connections[conn][DPORT] = info[4]
                detect_ipv4(connections[conn])
                # TODO maybe extract more information

    return connections


def interesting_tcp_graph(flow_name, connections):
    """ Return True if the MPTCP graph is worthy, else False
        This function assumes that a graph is interesting if it has at least one connection that
        if not 127.0.0.1 -> 127.0.0.1
        Note that is the graph is interesting and IPv4, indicates if the traffic is Wi-Fi or rmnet
    """
    if not connections[flow_name][TYPE] == 'IPv4':
        return True
    if not (connections[flow_name][SADDR] == LOCALHOST_IPv4 and
            connections[flow_name][DADDR] == LOCALHOST_IPv4):
        indicates_wifi_or_rmnet(connections[flow_name])
        return True
    return False


def prepare_gpl_file(pcap_fname, gpl_fname):
    """ Return a gpl file name of a ready-to-use gpl file or None if an error
        occurs
    """
    try:
        gpl_fname_ok = gpl_fname[:-4] + '_ok.gpl'
        gpl_file = open(gpl_fname, 'r')
        gpl_file_ok = open(gpl_fname_ok, 'w')
        data = gpl_file.readlines()
        # Copy everything but the last 4 lines
        for line in data[:-4]:
            gpl_file_ok.write(line)
        # Give the pdf filename where the graph will be stored
        pdf_fname = os.path.join(graph_dir_exp,
                                 pcap_fname[
                                     len(trace_dir_exp) + 1:-5] + "_" + gpl_fname[:-4]
                                 + '.pdf')

        # Needed to give again the line with all data (5th line from the end)
        # Better to reset the plot (to avoid potential bugs)
        to_write = "set output '" + pdf_fname + "'\n" \
            + "set terminal pdf\n" \
            + data[-5] \
            + "set terminal pdf\n" \
            + "set output\n" \
            + "reset\n"
        gpl_file_ok.write(to_write)
        # Don't forget to close files
        gpl_file.close()
        gpl_file_ok.close()
        return gpl_fname_ok
    except IOError as e:
        print('IOError for graph file with ' + gpl_fname + ': skip')
        return None


def get_flow_name(xpl_fname):
    """ Return the flow name in the form 'a2b' (and not 'b2a') """
    # Basic information is contained between the two last '_'
    last_us_index = xpl_fname.rindex("_")
    nearly_last_us_index = xpl_fname.rindex("_", 0, last_us_index)
    flow_name = xpl_fname[nearly_last_us_index + 1:last_us_index]

    # Need to check if we need to reverse the flow name
    two_index = flow_name.index("2")
    left_letter = flow_name[two_index - 1]
    right_letter = flow_name[-1]
    if right_letter < left_letter:
        # Swap those two characters
        chars = list(flow_name)
        chars[two_index - 1] = right_letter
        chars[-1] = left_letter
        return ''.join(chars)
    else:
        return flow_name


def process_tcptrace_cmd(cmd):
    """ Launch the command cmd given in argument, and return a dictionary containing information
        about connections of the pcap file analyzed
        Options -l and --csv should be set
    """
    pcap_flow_data = pcap_fname[:-5] + '.out'
    flow_data_file = open(pcap_flow_data, 'w+')
    if subprocess.call(cmd.split(), stdout=flow_data_file) != 0:
        print("Error of tcptrace with " + pcap_fname + "; skip process")
        return
    connections = extract_tcp_flow_data(flow_data_file)

    # Don't forget to close and remove pcap_flow_data
    flow_data_file.close()
    os.remove(pcap_flow_data)
    return connections


def get_connection_data_with_ip_port(connections, ip, port, dst=True):
    """ Get data for connection with destination IP ip and port port in connections
        If no connection found, return None
        Support for dst=False will be provided if needed
    """
    for conn, data in connections.iteritems():
        if data[DADDR] == ip and data[DPORT] == port:
            return data

    # If reach this, no matching connection found
    return None


def correct_tcp_trace(pcap_fname):
    """ Make the link between two unidirectional connections that form one bidirectional one """
    cmd = "tcptrace -l --csv " + pcap_fname
    connections = process_tcptrace_cmd(cmd)

    # Create the remaining_file
    remain_pcap_fname = pcap_fname[:-5] + "__rem.pcap"
    cmd = 'cp ' + pcap_fname + " " + remain_pcap_fname
    if subprocess.call(cmd.split()) != 0:
        print("Error when copying " + pcap_fname + ": skip tcp correction")
        return

    num = 0
    for conn, data in connections.iteritems():
        if data[DADDR] == LOCALHOST_IPv4 and data[DPORT] == PORT_RSOCKS:
            other_data = get_connection_data_with_ip_port(
                data[SADDR], data[SPORT])
            if other_data:
                # Split on the port criterion
                condition = '(tcp.srcport==' + \
                    data[SPORT] + ')or(tcp.dstport==' + data[SPORT] + ')'
                tmp_split_fname = pcap_fname[:-5] + "__tmp.pcap"
                cmd = "tshark -r " + remain_pcap_fname + " -Y '" + \
                    condition + "' -w " + split_fname
                if subprocess.call(cmd.split()) != 0:
                    print(
                        "Error when tshark port " + data[SPORT] + ": skip tcp correction")
                    return
                tmp_remain_fname = pcap_fname[:-5] + "__tmprem.pcap"
                cmd = "tshark -r " + remain_pcap_fname + " -Y '" + \
                    "!(" + condition + ")" + "' -w " + tmp_remain_fname
                if subprocess.call(cmd.split()) != 0:
                    print(
                        "Error when tshark port !" + data[SPORT] + ": skip tcp correction")
                    return
                cmd = "mv " + tmp_remain_fname + " " + remain_pcap_fname

                # Replace meaningless IP and port with the "real" values
                split_fname = pcap_fname[:-5] + "__" + str(num) + ".pcap"
                cmd = "tcprewrite --portmap=" + data[DPORT] + ":" + other_data[SPORT] + " --pnat=" + data[
                    DADDR] + ":" + other_data[SADDR] + " --infile=" + tmp_split_fname + " --outfile=" + split_fname
                if subprocess.call(cmd.split()) != 0:
                    print(
                        "Error with tcprewrite " + data[SPORT] + ": skip tcp correction")
                    return
                num += 1
                os.remove(tmp_split_fname)

    # Merge small pcap files into a unique one
    to_merge = ""
    for subpcap_fname in glob.glob(pcap_fname[:-5] + '__*.pcap'):
        to_merge += " " + subpcap_fname

    cmd = "mergecap -w " + pcap_fname + " " + to_merge
    if subprocess.call(cmd.split()) != 0:
        print(
            "Error with mergecap " + pcap_fname + ": skip tcp correction")
        return


def process_tcp_trace(pcap_fname):
    """ Process a tcp pcap file and generate graphs of its connections """
    # -C for color, -S for sequence numbers, -T for throughput graph
    # -zxy to plot both axes to 0
    # -n to avoid name resolution
    # -y to remove some noise in sequence graphs
    # -l for long output
    # --csv for csv file
    cmd = "tcptrace --output_dir=" + os.getcwd() + " --output_prefix=" \
        + pcap_fname[:-5] + "_ -C -S -T -zxy -n -y -l --csv --noshowzwndprobes --noshowoutorder --noshowrexmit "\
        + "--noshowsacks --noshowzerowindow --noshowurg --noshowdupack3 --noshowzerolensegs " \
        + pcap_fname
    connections = process_tcptrace_cmd(cmd)

    # The tcptrace call will generate .xpl files to cope with
    for xpl_fname in glob.glob(os.path.join(trace_dir_exp, pcap_fname[len(trace_dir_exp) + 1:-5]
                                            + '*.xpl')):
        flow_name = get_flow_name(xpl_fname)
        if interesting_tcp_graph(flow_name, connections):
            cmd = "xpl2gpl " + xpl_fname
            if subprocess.call(cmd.split()) != 0:
                print("Error of xpl2gpl with " + xpl_fname + "; skip xpl file")
                continue
            prefix_fname = xpl_fname[len(trace_dir_exp) + 1:-4]
            gpl_fname = prefix_fname + '.gpl'
            gpl_fname_ok = prepare_gpl_file(pcap_fname, gpl_fname)
            if gpl_fname_ok:
                cmd = "gnuplot " + gpl_fname_ok
                if subprocess.call(cmd.split()) != 0:
                    print(
                        "Error of tcptrace with " + pcap_fname + "; skip process")
                    return

            # Delete gpl, xpl and others files generated
            try:
                os.remove(gpl_fname)
                os.remove(gpl_fname_ok)
                try:
                    os.remove(prefix_fname + '.datasets')
                except OSError as e2:
                    # Throughput graphs have not .datasets file
                    pass
                os.remove(prefix_fname + '.labels')
            except OSError as e:
                print(str(e) + ": skipped")
        try:
            os.remove(xpl_fname)
        except OSError as e:
            print(str(e) + ": skipped")

    # Save connections info
    save_connections(pcap_fname, connections)

##################################################
##                     MAIN                     ##
##################################################

check_directory_exists(graph_dir_exp)
check_directory_exists(stat_dir_exp)
# If file is a .pcap, use it for (mp)tcptrace
for pcap_fname in glob.glob(os.path.join(trace_dir_exp, '*.pcap')):
    pcap_filename = pcap_fname[len(trace_dir_exp) + 1:]
    # Cleaning, if needed (in future pcap, tcpdump should do the job)
    if args.clean:
        clean_loopback_pcap(pcap_fname)
    # Prefix of the name determine the protocol used
    if pcap_filename.startswith('mptcp'):
        process_mptcp_trace(pcap_fname)
    elif pcap_filename.startswith('tcp'):
        correct_tcp_trace(pcap_fname)
        process_tcp_trace(pcap_fname)
    else:
        print(pcap_fname + ": don't know the protocol used; skipped")

    print('End for file ' + pcap_fname)
    os.remove(pcap_fname)

print('End of analyze')

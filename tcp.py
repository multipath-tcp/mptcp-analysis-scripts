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
#  Contains code related to the processing of TCP traces

from __future__ import print_function

##################################################
##                   IMPORTS                    ##
##################################################

from common import *

import glob
import os
import subprocess
import sys

##################################################
##           CONNECTION DATA RELATED            ##
##################################################


class TCPConnection(BasicConnection):
    """ Represent a TCP connection """
    flow = BasicFlow()


def compute_duration(info):
    """ Given the output of tcptrace as an array, compute the duration of a tcp connection
        The computation done (in term of tcptrace's attributes) is last_packet - first_packet
    """
    first_packet = float(info[5])
    last_packet = float(info[6])
    return last_packet - first_packet


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
                indicates_wifi_or_rmnet(connections[conn])
                connections[conn][DURATION] = compute_duration(info)
                connections[conn][PACKS_S2D] = int(info[7])
                connections[conn][PACKS_D2S] = int(info[8])
                # Note that this count is about unique_data_bytes
                connections[conn][BYTES_S2D] = int(info[21])
                connections[conn][BYTES_D2S] = int(info[22])
                # TODO maybe extract more information

    return connections

##################################################
##        CONNECTION IDENTIFIER RELATED         ##
##################################################


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


##################################################
##                   TCPTRACE                   ##
##################################################


def process_tcptrace_cmd(cmd, pcap_fname):
    """ Launch the command cmd given in argument, and return a dictionary containing information
        about connections of the pcap file analyzed
        Options -n, -l and --csv should be set
    """
    pcap_flow_data = pcap_fname[:-5] + '.out'
    flow_data_file = open(pcap_flow_data, 'w+')
    if subprocess.call(cmd, stdout=flow_data_file) != 0:
        print("Error of tcptrace with " + pcap_fname + "; skip process", file=sys.stderr)
        return
    connections = extract_tcp_flow_data(flow_data_file)

    # Don't forget to close and remove pcap_flow_data
    flow_data_file.close()
    os.remove(pcap_flow_data)
    return connections

##################################################
##               CLEANING RELATED               ##
##################################################


def get_connection_data_with_ip_port_tcp(connections, ip, port, dst=True):
    """ Get data for TCP connection with destination IP ip and port port in connections
        If no connection found, return None
        Support for dst=False will be provided if needed
    """
    for conn, data in connections.iteritems():
        if data[DADDR] == ip and data[DPORT] == port:
            return data

    # If reach this, no matching connection found
    return None


def merge_and_clean_sub_pcap(pcap_fname, print_out=sys.stdout):
    """ Merge pcap files with name beginning with pcap_fname followed by two underscores and delete
        them
    """
    cmd = ['mergecap', '-w', pcap_fname]
    for subpcap_fname in glob.glob(pcap_fname[:-5] + '__*.pcap'):
        cmd.append(subpcap_fname)

    if subprocess.call(cmd, stdout=print_out) != 0:
        print(
            "Error with mergecap " + pcap_fname + ": skip tcp correction", file=sys.stderr)
        return
    for subpcap_fname in cmd[3:]:
        os.remove(subpcap_fname)


def split_and_replace(pcap_fname, remain_pcap_fname, data, other_data, num, print_out=sys.stdout):
    """ Split remain_pcap_fname and replace DADDR and DPORT of data by SADDR and DADDR of other_data
        num will be the numerotation of the splitted file
    """
    # Split on the port criterion
    condition = '(tcp.srcport==' + \
        data[SPORT] + ')or(tcp.dstport==' + data[SPORT] + ')'
    tmp_split_fname = pcap_fname[:-5] + "__tmp.pcap"
    cmd = ['tshark', '-r', remain_pcap_fname, '-Y', condition, '-w', tmp_split_fname]
    if subprocess.call(cmd, stdout=print_out) != 0:
        print(
            "Error when tshark port " + data[SPORT] + ": skip tcp correction", file=sys.stderr)
        return -1
    tmp_remain_fname = pcap_fname[:-5] + "__tmprem.pcap"
    cmd[4] = "!(" + condition + ")"
    cmd[6] = tmp_remain_fname
    if subprocess.call(cmd, stdout=print_out) != 0:
        print(
            "Error when tshark port !" + data[SPORT] + ": skip tcp correction", file=sys.stderr)
        return -1
    cmd = ['mv', tmp_remain_fname, remain_pcap_fname]
    if subprocess.call(cmd, stdout=print_out) != 0:
        print(
            "Error when moving " + tmp_remain_fname + " to " + remain_pcap_fname +  ": skip tcp correction", file=sys.stderr)
        return -1

    # Replace meaningless IP and port with the "real" values
    split_fname = pcap_fname[:-5] + "__" + str(num) + ".pcap"
    cmd = ['tcprewrite',
           "--portmap=" + data[DPORT] + ":" + other_data[SPORT],
           "--pnat=" + data[DADDR] + ":" + other_data[SADDR],
           "--infile=" + tmp_split_fname,
           "--outfile=" + split_fname]
    if subprocess.call(cmd, stdout=print_out) != 0:
        print(
            "Error with tcprewrite " + data[SPORT] + ": skip tcp correction", file=sys.stderr)
        return -1
    os.remove(tmp_split_fname)
    return 0


def correct_trace(pcap_fname, print_out=sys.stdout):
    """ Make the link between two unidirectional connections that form one bidirectional one
        Do this also for mptcp, because mptcptrace will not be able to find all conversations
    """
    cmd = ['tcptrace', '-n', '-l', '--csv', pcap_fname]
    connections = process_tcptrace_cmd(cmd, pcap_fname)
    # Create the remaining_file
    remain_pcap_fname = copy_remain_pcap_file(pcap_fname, print_out=print_out)
    if not remain_pcap_fname:
        return

    num = 0
    for conn, data in connections.iteritems():
        if data[DADDR] == LOCALHOST_IPv4 and data[DPORT] == PORT_RSOCKS:
            other_data = get_connection_data_with_ip_port_tcp(
                connections, data[SADDR], data[SPORT])
            if other_data:
                if split_and_replace(pcap_fname, remain_pcap_fname, data, other_data, num) != 0:
                    print("Stop correcting trace " + pcap_fname, file=print_out)
                    return
        num += 1
        print(os.path.basename(pcap_fname) + ": Corrected: " + str(num) + "/" + str(len(connections)), file=print_out)

    # Merge small pcap files into a unique one
    merge_and_clean_sub_pcap(pcap_fname)

##################################################
##                   TCPTRACE                   ##
##################################################


def interesting_tcp_graph(flow_name, connections):
    """ Return True if the MPTCP graph is worthy, else False
        This function assumes that a graph is interesting if it has at least one connection that
        if not 127.0.0.1 -> 127.0.0.1
    """
    return (not connections[flow_name][TYPE] == 'IPv4' or connections[flow_name][IF])


def prepare_gpl_file(pcap_fname, gpl_fname, graph_dir_exp):
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
                                 gpl_fname[:-4] + '.pdf')

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
        print('IOError for graph file with ' + gpl_fname + ': skip', file=sys.stderr)
        return None


def process_tcp_trace(pcap_fname, graph_dir_exp, stat_dir_exp, print_out=sys.stdout):
    """ Process a tcp pcap file and generate graphs of its connections """
    # -C for color, -S for sequence numbers, -T for throughput graph
    # -zxy to plot both axes to 0
    # -n to avoid name resolution
    # -y to remove some noise in sequence graphs
    # -l for long output
    # --csv for csv file
    cmd = ['tcptrace', '--output_dir=' + os.getcwd(),
        '--output_prefix=' + os.path.basename(pcap_fname[:-5]) + '_', '-C', '-S', '-T', '-zxy',
        '-n', '-y', '-l', '--csv', '--noshowzwndprobes', '--noshowoutorder', '--noshowrexmit',
        '--noshowsacks', '--noshowzerowindow', '--noshowurg', '--noshowdupack3',
        '--noshowzerolensegs', pcap_fname]

    connections = process_tcptrace_cmd(cmd, pcap_fname)

    # The tcptrace call will generate .xpl files to cope with
    for xpl_fname in glob.glob(os.path.join(os.getcwd(), os.path.basename(pcap_fname[:-5]) + '*.xpl')):
        flow_name = get_flow_name(xpl_fname)
        if interesting_tcp_graph(flow_name, connections):
            cmd = ['xpl2gpl', xpl_fname]
            if subprocess.call(cmd, stdout=print_out) != 0:
                print("Error of xpl2gpl with " + xpl_fname + "; skip xpl file", file=sys.stderr)
                continue
            prefix_fname = os.path.basename(xpl_fname)[:-4]
            gpl_fname = prefix_fname + '.gpl'
            gpl_fname_ok = prepare_gpl_file(pcap_fname, gpl_fname, graph_dir_exp)
            if gpl_fname_ok:
                devnull = open(os.devnull, 'w')
                cmd = ['gnuplot', gpl_fname_ok]
                if subprocess.call(cmd, stdout=devnull) != 0:
                    print(
                        "Error of tcptrace with " + pcap_fname + "; skip process", file=sys.stderr)
                    return
                devnull.close()

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
                print(str(e) + ": skipped", file=sys.stderr)
        try:
            os.remove(xpl_fname)
        except OSError as e:
            print(str(e) + ": skipped", file=sys.stderr)

    # Save connections info
    save_connections(pcap_fname, stat_dir_exp, connections)

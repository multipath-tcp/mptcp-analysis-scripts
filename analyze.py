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
# To install on this machine: numpy, mptcptrace, tcptrace, tshark, tcpreplay

from __future__ import print_function

##################################################
##                   IMPORTS                    ##
##################################################

import argparse
import common as co
import mptcp
import os
import os.path
from pymongo import Connection
import subprocess
import sys
import tcp
import threading
import traceback

from multiprocessing import Process


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
# The default number of threads
DEF_NB_THREADS = 1

##################################################
##                   ARGUMENTS                  ##
##################################################

parser = argparse.ArgumentParser(
    description="Analyze pcap files of TCP or MPTCP connections")
parser.add_argument("-i",
                    "--input", help="input directory/file of the (possibly compressed) pcap files", default=DEF_IN_DIR)
parser.add_argument("-t",
                    "--trace", help="temporary directory that will be used to store uncompressed "
                    + "pcap files", default=DEF_TRACE_DIR)
parser.add_argument("-g",
                    "--graph", help="directory where the graphs of the pcap files will be stored", default=DEF_GRAPH_DIR)
parser.add_argument("-s",
                    "--stat", help="directory where the stats of the pcap files will be stored", default=co.DEF_STAT_DIR)
parser.add_argument("-a",
                    "--aggl", help="directory where data of agglomerated graphs will be stored", default=co.DEF_AGGL_DIR)
parser.add_argument("-r",
                    "--rtt", help="directory where data of round-trip-time will be stored", default=co.DEF_RTT_DIR)
parser.add_argument("-R",
                    "--rtt-subflow", help="directory where data of round-trip-time of subflows of MPTCP will be stored", default=co.DEF_RTT_SUBFLOW_DIR)
parser.add_argument("-F",
                    "--failed-conns", help="directory that contains failed TCP connections to establish subflow", default=co.DEF_FAILED_CONNS_DIR)
parser.add_argument("-A",
                    "--acksize", help="directory where acksize info of connections are stored", default=co.DEF_ACKSIZE_DIR)
parser.add_argument("-p", "--pcap",
                    help="analyze only pcap files containing the given string (default any, wlan0 and rmnet0)",
                    nargs="+", default=["_" + co.DEF_IFACE + ".", "_wlan0.", "_rmnet0."])
parser.add_argument("-j",
                    "--threads", type=int, help="process the analyse separated threads", default=DEF_NB_THREADS)
parser.add_argument("-l",
                    "--stderr", help="log to stderr", action="store_true")
parser.add_argument("-k",
                    "--keep", help="keep the original file with -k option of gunzip, if it exists",
                    action="store_true")
parser.add_argument("-c",
                    "--clean", help="remove noisy traffic on lo", action="store_true")
parser.add_argument("-C",
                    "--not-correct", help="do not correct traces, implies no preprocessing", action="store_true")
parser.add_argument("-G",
                    "--not-graph", help="do not produce graphes and keep corrected traces, implies -P", action="store_true")
parser.add_argument("-P",
                    "--not-purge", help="do not remove corrected traces", action="store_true")
parser.add_argument("-b",
                    "--min-bytes", help="only plot graphs of connections with at least a given amount of bytes", default=0)
parser.add_argument("-W",
                    "--cwin", help="plot congestion window graphs and aggregation graphs", action="store_true")
parser.add_argument("-M",
                    "--is-mptcp", help="don't check on filename, always process traces as MPTCP ones", action="store_true")
parser.add_argument("-D",
                    "--use-db", help="ask IP address of each interface to the MongoDB", action="store_true")
parser.add_argument("-L",
                    "--light", help="don't process RTT or throughput in detail to save time", action="store_true")

args = parser.parse_args()

in_dir_exp = os.path.abspath(os.path.expanduser(args.input))
# ~/graphs -> /home/mptcp/graphs_lo ; ../graphs/ -> /home/mptcp/graphs_lo
trace_dir_exp = co.get_dir_from_arg(args.trace, args.pcap[0])
graph_dir_exp = co.get_dir_from_arg(args.graph, args.pcap[0])
stat_dir_exp = co.get_dir_from_arg(args.stat,  args.pcap[0])
aggl_dir_exp = co.get_dir_from_arg(args.aggl,  args.pcap[0])
rtt_dir_exp = co.get_dir_from_arg(args.rtt,  args.pcap[0])
rtt_subflow_dir_exp = co.get_dir_from_arg(args.rtt_subflow,  args.pcap[0])
failed_conns_dir_exp = co.get_dir_from_arg(args.failed_conns,  args.pcap[0])
acksize_dir_exp = co.get_dir_from_arg(args.acksize, args.pcap[0])

if os.path.isdir(in_dir_exp):
    # add the basename of the input dir
    base_dir = os.path.basename(in_dir_exp)  # 20150215-013001_d8cac271ad6d544930b0e804383c19378ed4908c
    parent_dir = os.path.basename(os.path.dirname(in_dir_exp))  # TCPDump or TCPDump_bad_simulation
    trace_dir_exp = os.path.join(trace_dir_exp, parent_dir, base_dir)
    graph_dir_exp = os.path.join(graph_dir_exp, parent_dir, base_dir)
    stat_dir_exp = os.path.join(stat_dir_exp,  parent_dir, base_dir)
    aggl_dir_exp = os.path.join(aggl_dir_exp,  parent_dir, base_dir)
    rtt_dir_exp = os.path.join(rtt_dir_exp,  parent_dir, base_dir)
    rtt_subflow_dir_exp = os.path.join(rtt_subflow_dir_exp, parent_dir, base_dir)
    failed_conns_dir_exp = os.path.join(failed_conns_dir_exp, parent_dir, base_dir)
    acksize_dir_exp = os.path.join(acksize_dir_exp, parent_dir, base_dir)

if args.stderr:
    print_out = sys.stderr
else:
    print_out = sys.stdout

##################################################
##                 PREPROCESSING                ##
##################################################


def uncompress_file(filename, dirpath):
    if any(match in filename for match in args.pcap):
        # Files from UI tests will be compressed; unzip them
        if filename.endswith('.pcap.gz'):
            output_filepath = os.path.join(trace_dir_exp, filename[:-3])
            # if args.not_correct:
            #     return output_filepath
            if os.path.exists(output_filepath):
                print("Do no uncompress file: already exists " + filename, file=sys.stderr)
                return output_filepath
            else:
                print("Uncompressing " + filename + " to " + trace_dir_exp, file=print_out)
                output = open(output_filepath, 'w')
                cmd = ['gunzip', '-c', '-9', os.path.join(dirpath, filename)]
                if args.keep:
                    cmd.insert(1, '-k')
                if subprocess.call(cmd, stdout=output) != 0:
                    print("Error when uncompressing " + filename, file=sys.stderr)
                    output.close()
                else:
                    output.close()
                    return output_filepath
        elif filename.endswith('.pcap'):
            output_filepath = os.path.join(trace_dir_exp, filename)
            # if args.not_correct:
            #     return output_filepath
            if os.path.exists(output_filepath):
                print("Do no copy file: already exists " + filename, file=sys.stderr)
                return output_filepath
            else:
                # Move the file to out_dir_exp
                print("Copying " + filename + " to " + trace_dir_exp, file=print_out)
                cmd = ['cp', os.path.join(dirpath, filename), output_filepath]
                if subprocess.call(cmd, stdout=print_out) != 0:
                    print("Error when moving " + filename, file=sys.stderr)
                else:
                    return output_filepath
        else:
            print(filename + ": not in a valid format, skipped", file=sys.stderr)
    return False


def add_if_valid(list, item):
    if item:
        list.append(item)

pcap_list = []
co.check_directory_exists(trace_dir_exp)
if os.path.isdir(in_dir_exp):
    for dirpath, dirnames, filenames in os.walk(in_dir_exp):
        for filename in filenames:
            add_if_valid(pcap_list, uncompress_file(filename, dirpath))
else:
    add_if_valid(pcap_list, uncompress_file(os.path.basename(in_dir_exp),
                                            os.path.dirname(in_dir_exp)))

pcap_list_len = len(pcap_list)


##################################################
##                  FETCH DB                    ##
##################################################

if args.use_db:
    connection = Connection('localhost', 27017)
    db = connection.mpctrl
    collection = db.handover
    co.IP_WIFI = collection.distinct('ipWifi4') + collection.distinct('ipWifi6')
    co.IP_CELL = collection.distinct('ipRMNet4') + collection.distinct('ipRMNet6')
    print("IP_WIFI", co.IP_WIFI)
    print("IP_CELL", co.IP_CELL)
    connection.close()


##################################################
##                   THREADS                    ##
##################################################

def launch_analyze_pcap(pcap_filepath, clean, correct, graph, purge, cwin):
    pcap_filename = os.path.basename(pcap_filepath)
    # Cleaning, if needed (in future pcap, tcpdump should do the job)
    if clean:
        co.clean_loopback_pcap(pcap_filepath, print_out=print_out)
    # Prefix of the name determine the protocol used
    if args.is_mptcp or pcap_filename.startswith('mptcp'):
        if correct:
            tcp.correct_trace(pcap_filepath, print_out=print_out)
        # we need to change dir, do that in a new process
        if graph:
            p = Process(target=mptcp.process_trace, args=(
                pcap_filepath, graph_dir_exp, stat_dir_exp, aggl_dir_exp, rtt_dir_exp, rtt_subflow_dir_exp, failed_conns_dir_exp, acksize_dir_exp, cwin,), kwargs={'min_bytes': args.min_bytes, 'light': args.light})
            p.start()
            p.join()
    elif pcap_filename.startswith('tcp'):
        if correct:
            tcp.correct_trace(pcap_filepath, print_out=print_out)
        if graph:
            tcp.process_trace(pcap_filepath, graph_dir_exp, stat_dir_exp, aggl_dir_exp, rtt_dir_exp, rtt_subflow_dir_exp, failed_conns_dir_exp, cwin,
                              print_out=print_out, min_bytes=args.min_bytes, light=args.light)
    else:
        print(pcap_filepath + ": don't know the protocol used; skipped", file=sys.stderr)

    print('End for file ' + pcap_filepath, file=print_out)
    if purge and graph:  # if we just want to correct traces, do not remove them
        os.remove(pcap_filepath)


def thread_launch(thread_id, clean, correct, graph, purge, cwin):
    global pcap_list
    while True:
        try:
            pcap_filepath = pcap_list.pop()
        except IndexError:  # no more thread
            break
        analyze_no = str(pcap_list_len - len(pcap_list)) + "/" + str(pcap_list_len)
        print("Thread " + str(thread_id) + ": Analyze: " + pcap_filepath + " (" + analyze_no + ")", file=print_out)
        try:
            launch_analyze_pcap(pcap_filepath, clean, correct, graph, purge, cwin)
        except:
            print(traceback.format_exc(), file=sys.stderr)
            print('Error when analyzing ' + pcap_filepath + ': skip', file=sys.stderr)
    print("Thread " + str(thread_id) + ": End", file=print_out)

##################################################
##                     MAIN                     ##
##################################################

co.check_directory_exists(graph_dir_exp)
co.check_directory_exists(os.path.join(graph_dir_exp, co.TSG_THGPT_DIR))
co.check_directory_exists(os.path.join(graph_dir_exp, co.CWIN_DIR))
co.check_directory_exists(os.path.join(graph_dir_exp, co.AGGL_DIR))
co.check_directory_exists(os.path.join(graph_dir_exp, co.CSV_DIR))
co.check_directory_exists(os.path.join(graph_dir_exp, co.DEF_RTT_DIR))
co.check_directory_exists(stat_dir_exp)
co.check_directory_exists(aggl_dir_exp)
co.check_directory_exists(rtt_dir_exp)
co.check_directory_exists(rtt_subflow_dir_exp)
co.check_directory_exists(failed_conns_dir_exp)
co.check_directory_exists(acksize_dir_exp)
# If file is a .pcap, use it for (mp)tcptrace
pcap_list.reverse()  # we will use pop: use the natural order

threads = []
args.threads = min(args.threads, pcap_list_len)
if args.threads > 1:
    # Launch new thread
    for thread_id in range(args.threads):
        thread = threading.Thread(target=thread_launch,
                                  args=(thread_id, args.clean,
                                        not args.not_correct, not args.not_graph, not args.not_purge, args.cwin))
        thread.start()
        threads.append(thread)
    # Wait
    for thread in threads:
        thread.join()
else:
    thread_launch(0, args.clean, not args.not_correct, not args.not_graph, not args.not_purge, args.cwin)


print('End of analyze', file=print_out)

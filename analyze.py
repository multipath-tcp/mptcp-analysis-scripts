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
# xpl2gpl, tshark, tcpreplay

from __future__ import print_function

##################################################
##                   IMPORTS                    ##
##################################################

import argparse
import common as co
import mptcp
import os
import os.path
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
# The default stat directory
DEF_STAT_DIR = 'stats'
# The default aggl directory
DEF_AGGL_DIR = 'aggls'
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
    "--stat", help="directory where the stats of the pcap files will be stored", default=DEF_STAT_DIR)
parser.add_argument("-a",
    "--aggl", help="directory where data of agglomerated graphs will be stored", default=DEF_AGGL_DIR)
parser.add_argument("-p",
    "--pcap", help="analyze only pcap files containing the given string (default lo)", default="_lo.")
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
args = parser.parse_args()

in_dir_exp = os.path.abspath(os.path.expanduser(args.input))
trace_dir_exp = os.path.abspath(os.path.expanduser(args.trace))
graph_dir_exp = os.path.abspath(os.path.expanduser(args.graph))
stat_dir_exp = os.path.abspath(os.path.expanduser(args.stat))
aggl_dir_exp = os.path.abspath(os.path.expanduser(args.aggl))

if os.path.isdir(in_dir_exp):
    base_dir = os.path.basename(in_dir_exp)
    trace_dir_exp = os.path.join(trace_dir_exp, base_dir)
    graph_dir_exp = os.path.join(graph_dir_exp, base_dir)
    stat_dir_exp  = os.path.join(stat_dir_exp,  base_dir)
    aggl_dir_exp  = os.path.join(aggl_dir_exp,  base_dir)

if args.stderr:
    print_out = sys.stderr
else:
    print_out = sys.stdout

##################################################
##                 PREPROCESSING                ##
##################################################

def uncompress_file(fname, dirpath):
    if args.pcap in fname:
        # Files from UI tests will be compressed; unzip them
        if fname.endswith('.gz'):
            output_file = os.path.join(trace_dir_exp, fname[:-3])
            if args.not_correct:
                return output_file
            else:
                print("Uncompressing " + fname + " to " + trace_dir_exp, file=print_out)
                output = open(output_file, 'w')
                cmd = ['gunzip', '-c', '-9', os.path.join(dirpath, fname)]
                if args.keep:
                    cmd.insert(1, '-k')
                if subprocess.call(cmd, stdout=output) != 0:
                    print("Error when uncompressing " + fname, file=sys.stderr)
                    output.close()
                else:
                    output.close()
                    return output_file
        elif fname.endswith('.pcap'):
            output_file = os.path.join(trace_dir_exp, fname)
            if args.not_correct:
                return output_file
            else:
                # Move the file to out_dir_exp
                print("Copying " + fname + " to " + trace_dir_exp, file=print_out)
                cmd = ['cp', os.path.join(dirpath, fname), output_file]
                if subprocess.call(cmd, stdout=print_out) != 0:
                    print("Error when moving " + fname, file=sys.stderr)
                else:
                    return output_file
        else:
            print(fname + ": not in a valid format, skipped", file=sys.stderr)
    return False

def add_if_valid(list, item):
    if item:
        list.append(item)

pcap_list = []
co.check_directory_exists(trace_dir_exp)
if os.path.isdir(in_dir_exp):
    for dirpath, dirnames, filenames in os.walk(in_dir_exp):
        for fname in filenames:
            add_if_valid(pcap_list, uncompress_file(fname, dirpath))
else:
    add_if_valid(pcap_list, uncompress_file(os.path.basename(in_dir_exp),
                                            os.path.dirname(in_dir_exp)))



##################################################
##                   THREADS                    ##
##################################################

def launch_analyze_pcap(pcap_fname, clean, correct, graph, purge):
    pcap_filename = os.path.basename(pcap_fname)
    # Cleaning, if needed (in future pcap, tcpdump should do the job)
    if clean:
        co.clean_loopback_pcap(pcap_fname, print_out=print_out)
    # Prefix of the name determine the protocol used
    if pcap_filename.startswith('mptcp'):
        if correct:
            tcp.correct_trace(pcap_fname, print_out=print_out)
        # we need to change dir, do that in a new process
        if graph:
            p = Process(target=mptcp.process_trace, args=(pcap_fname, graph_dir_exp, stat_dir_exp, aggl_dir_exp,), kwargs={'min_bytes': args.min_bytes})
            p.start()
            p.join()
    elif pcap_filename.startswith('tcp'):
        if correct:
            tcp.correct_trace(pcap_fname, print_out=print_out)
        if graph:
            tcp.process_trace(pcap_fname, graph_dir_exp, stat_dir_exp, aggl_dir_exp, print_out=print_out, min_bytes=args.min_bytes)
    else:
        print(pcap_fname + ": don't know the protocol used; skipped", file=sys.stderr)

    print('End for file ' + pcap_fname, file=print_out)
    if purge and graph: # if we just want to correct traces, do not remove them
        os.remove(pcap_fname)

def thread_launch(thread_id, clean, correct, graph, purge):
    global pcap_list
    while True:
        try:
            pcap_fname = pcap_list.pop()
        except IndexError: # no more thread
            break
        print("Thread " + str(thread_id) + ": Analyze: " + pcap_fname, file=print_out)
        try:
            launch_analyze_pcap(pcap_fname, clean, correct, graph, purge)
        except:
            print(traceback.format_exc(), file=sys.stderr)
            print('Error when analyzing ' + pcap_fname + ': skip', file=sys.stderr)
    print("Thread " + str(thread_id) + ": End", file=print_out)

##################################################
##                     MAIN                     ##
##################################################

co.check_directory_exists(graph_dir_exp)
co.check_directory_exists(stat_dir_exp)
co.check_directory_exists(aggl_dir_exp)
# If file is a .pcap, use it for (mp)tcptrace
pcap_list.reverse() # we will use pop: use the natural order

threads = []
args.threads = min(args.threads, len(pcap_list))
if args.threads > 1:
    # Launch new thread
    for thread_id in range(args.threads):
        thread = threading.Thread(target=thread_launch,
            args=(thread_id, args.clean,
                  not args.not_correct, not args.not_graph, not args.not_purge))
        thread.start()
        threads.append(thread)
    # Wait
    for thread in threads:
        thread.join()
else:
    thread_launch(0, args.clean, not args.not_correct, not args.not_graph, not args.not_purge)


print('End of analyze', file=print_out)

PCAP Measurement
================

What is it?
-----------
This repository contains scripts to analyze and create graphes from the generated pcap files from the [UI tests](https://github.com/MPTCP-smartphone-thesis/uitests).

Requirements
------------
If you want to use this script, make sure you have the following dependencies:
  * [mptcptrace](https://bitbucket.org/bhesmans/mptcptrace)
  * [matplotlib](http://matplotlib.org/)
  * [numpy](https://pypi.python.org/pypi/numpy/)
  * [pdflatex](http://www.tug.org/applications/pdftex/)
  * [tcpreplay](http://tcpreplay.appneta.com/wiki/installation.html#downloads)
  * [tcptrace](http://www.tcptrace.org/)
  * [tshark](https://www.wireshark.org/docs/man-pages/tshark.html)

Use it
------
To launch it, in a terminal, if you have your traces to analyze in an `input` folder, type

`./analyze`

To have more detailed information on how to use it, you can show the help by typing

`./analyze -h`

Once this first analysis done, you can agglomerate the different statistics obtained (by default in the `stats` folder) by typing

`./summary`

Again, to have more details about the possibilities of this script, please type

`./summary -h`

Details about the stats generated
---------------------------------
Statistics about analyzed traces are contained in a stats folder, by default `stats_any`.
Each file contains a dictionary of objects representing the connections, that can be read using `pickle.load(file)`.
Depending of the protocol indicated on the file, those objects are either `TCPConnection`s or `MPTCPConnection`s.
Both of them inherit from `BasicConnection`, defined in `common.py`.
Information related to connections is stored in the `attr` attribute, containing a dictionary.

The main difference between `TCPConnection` and `MPTCPConnection` is related to the number of (sub)flows they contain.
`TCPConnection` only has one flow, in the `flow` attribute, whereas `MPTPCConnection` can have more than one, in the dictionary `flows`.
In both cases, flows inherit from (or are) `BasicFlow`, which has the `attr` dictionary containing all information related to the flow.

Keys of `attr` dictionary are defined in `common.py`.

PCAP Measurement
================

What is it?
-----------
This repository contains scripts to analyze and create graphes from the generated pcap files from the [UI tests](https://github.com/MPTCP-smartphone-thesis/uitests).

Requirements
------------
If you want to use this script, make sure you have the following dependencies:
  * [gnuplot](http://www.gnuplot.info/)
  * [Gnuplot.py](http://gnuplot-py.sourceforge.net/)
  * [mptcptrace](https://bitbucket.org/bhesmans/mptcptrace)
  * [matplotlib](http://matplotlib.org/)
  * [numpy](https://pypi.python.org/pypi/numpy/)
  * [pdflatex](http://www.tug.org/applications/pdftex/)
  * [tcpreplay](http://tcpreplay.appneta.com/wiki/installation.html#downloads)
  * [tcptrace](http://www.tcptrace.org/)
  * [tshark](https://www.wireshark.org/docs/man-pages/tshark.html)
  * [xpl2gpl](http://www.tcptrace.org/xpl2gpl/)

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

README
===================

This is a fork of the original project from google code by Thomas
Pinckney: http://code.google.com/p/pymds/

Overview
===================

pymds is an authoritative DNS server which makes all name resolution
decisions using external modules. pymds itself cannot resolve
anything. Instead, it relies on plugins which convert names in
client queries into responses that pymds then sends.

pymds is not designed as a DNS client / resolver / cache. It will not
look up anything for. All it is designed to do is answer queries for a
specific domain. djbdns comes with an excellent resolver and cache if 
that's what you're looking for.

What's included
===================

This source distribution contains:

1) pymds -- The core DNS server itself.

2) pymdsfile -- A plugin for answering queries based on a text file
database. This is a "source" plugin in pymds parlance. See below for
the format of the database file syntax.

3) pymdsrr -- A plugin that randomizes the order of multiple A record
responses. This is a "filter" plugin as opposed to a "source"
plugin. Thus, it cannot resolve names to answers, only alter the
answers that some "source" plugin has already provided.

Usage
===================

You will need python 2.5 (which is what I test). Other versions of
Python may or may not work.

By default, pymds will listen on port 53 on all interfaces. You
can override the port and/or host to listen on with the -p and
-h options. 

By default, pymds will read configuration information from
a file named pymds.conf in the current directory. If you want
to specify a different file, list it on the command line. 

There must be a different configuration file for each domain
that pymds serves. If you want pymds to serve multiple domains,
list multiple configuration files on the command line.

# pymds [-p port] [-h host] [config1] [config2] ...

If you change a configuration file and want to reload pymds, send it
SIGHUP.

Configuration
===================

See the examples/ directory for configuration file examples.

Source, reporting bugs, etc
===================

See http://pymds.sourceforge.net for more information

#!/usr/bin/env python

# Copyright (c) 2009 Tom Pinckney
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
#
#     The above copyright notice and this permission notice shall be
#     included in all copies or substantial portions of the Software.
#
#     THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
#     EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
#     OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
#     NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
#     HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
#     WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#     FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
#     OTHER DEALINGS IN THE SOFTWARE.

import ConfigParser
import optparse
import signal
import socket
import struct
import sys

import utils



class DnsError(Exception):
    pass


class DnsServer(object):

    config_files = {}
    listen_host = '0.0.0.0'
    listen_port = 53
    debug = False

    def __init__(self, config_files=None, listen_host=None, listen_port=None):
        if config_files:
            self.config_files = config_files
        if listen_host:
            self.listen_host = listen_host
        if listen_port:
            self.listen_port = listen_port
        self.read_config()

    def __repr__(self):
        return '<pymds dns serving on %s:%d>' % (self.listen_host, self.listen_port)

    def add_config_file(self, config_file):
    """Adds a config to the list of config files, needs to call read_config() afterwards"""

        if config_file not in self.config_files.keys():
            self.config_files[config_file] = {}

    def set_port(self, port):
    """Sets the port who should bing ourselves to"""

        self.listen_port = int(port)

    def set_host(self, host):
    """Sets the host/ipaddress we should bing ourselves to"""

        self.listen_host = host

    def set_debug(self, debug=True):
        self.debug = debug

    def serve(self):
    """Serves forever"""

        udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udps.bind((self.listen_host, self.listen_port))
        #ns_resource_records, ar_resource_records = compute_name_server_resources(_name_servers)
        ns_resource_records = ar_resource_records = []
        while True:
            try:
                req_pkt, src_addr = udps.recvfrom(512)   # max UDP DNS pkt size
            except socket.error:
                continue
            qid = None
            try:
                exception_rcode = None
                try:
                    qid, question, qtype, qclass = self.parse_request(req_pkt)
                except:
                    exception_rcode = 1
                    raise Exception("could not parse query")
                question = map(lambda x: x.lower(), question)
                found = False
                for config in self.config_files.values():
                    if question[1:] == config['domain']:
                        query = question[0]
                    elif question == config['domain']:
                        query = ''
                    else:
                        continue
                    rcode, an_resource_records = config['source'].get_response(query, config['domain'], qtype, qclass, src_addr)
                    if rcode == 0 and 'filters' in config:
                        for f in config['filters']:
                            an_resource_records = f.filter(query, config['domain'], qtype, qclass, src_addr, an_resource_records)
                    resp_pkt = self.format_response(qid, question, qtype, qclass, rcode, an_resource_records, ns_resource_records, ar_resource_records)
                    found = True
                    if self.debug:
                        sys.stdout.write('Found question=%s, qtype=%s, qclass=%s\n' % (question, qtype, qclass))
                        sys.stdout.flush()
                    break
                if not found:
                    if self.debug:
                        sys.stderr.write('Unknown question=%s, qtype=%s, qclass=%s\n' % (question, qtype, qclass))
                        sys.stderr.flush()
                    exception_rcode = 3
                    raise Exception("query is not for our domain: %s" % ".".join(question))
            except:
                if qid:
                    if exception_rcode is None:
                        exception_rcode = 2
                    resp_pkt = self.format_response(qid, question, qtype, qclass, exception_rcode, [], [], [])
                else:
                    continue
            udps.sendto(resp_pkt, src_addr)

    def compute_name_server_resources(self, name_servers):
        ns = []
        ar = []
        for name_server, ip, ttl in name_servers:
            ns.append({'qtype':2, 'qclass':1, 'ttl':ttl, 'rdata':utils.labels2str(name_server)})
            ar.append({'qtype':1, 'qclass':1, 'ttl':ttl, 'rdata':struct.pack("!I", ip)})
        return ns, ar
        
    def parse_request(self, packet):
    """Parses the packet query to something we can give back"""

        hdr_len = 12
        header = packet[:hdr_len]
        qid, flags, qdcount, _, _, _ = struct.unpack('!HHHHHH', header)
        qr = (flags >> 15) & 0x1
        opcode = (flags >> 11) & 0xf
        rd = (flags >> 8) & 0x1
        #print "qid", qid, "qdcount", qdcount, "qr", qr, "opcode", opcode, "rd", rd
        if qr != 0 or opcode != 0 or qdcount == 0:
            raise DnsError("Invalid query")
        body = packet[hdr_len:]
        labels = []
        offset = 0
        while True:
            label_len, = struct.unpack('!B', body[offset:offset+1])
            offset += 1
            if label_len & 0xc0:
                raise DnsError("Invalid label length %d" % label_len)
            if label_len == 0:
                break
            label = body[offset:offset+label_len]
            offset += label_len
            labels.append(label)
        qtype, qclass= struct.unpack("!HH", body[offset:offset+4])
        if qclass != 1:
            raise DnsError("Invalid class: " + qclass)
        return (qid, labels, qtype, qclass)

    def format_response(self, qid, question, qtype, qclass, rcode, an_resource_records, ns_resource_records, ar_resource_records):
    """Formats the packet response"""

        resources = []
        resources.extend(an_resource_records)
        num_an_resources = len(an_resource_records)
        num_ns_resources = num_ar_resources = 0
        if rcode == 0:
            resources.extend(ns_resource_records)
            resources.extend(ar_resource_records)
            num_ns_resources = len(ns_resource_records)
            num_ar_resources = len(ar_resource_records)
        pkt = self.format_header(qid, rcode, num_an_resources, num_ns_resources, num_ar_resources)
        pkt += self.format_question(question, qtype, qclass)
        for resource in resources:
            pkt += self.format_resource(resource, question)
        return pkt

    def format_header(self, qid, rcode, ancount, nscount, arcount):
    """Formats the header to be used in the response packet"""

        flags = 0
        flags |= (1 << 15)
        flags |= (1 << 10)
        flags |= (rcode & 0xf)
        hdr = struct.pack("!HHHHHH", qid, flags, 1, ancount, nscount, arcount)
        return hdr

    def format_question(self, question, qtype, qclass):
    """Formats the question field to be used in the response packet"""

        q = utils.labels2str(question)
        q += struct.pack("!HH", qtype, qclass)
        return q

    def format_resource(self, resource, question):
    """Formats the resource fields to be used in the response packet"""

        r = ''
        r += utils.labels2str(question)
        r += struct.pack("!HHIH", resource['qtype'], resource['qclass'], resource['ttl'], len(resource['rdata']))
        r += resource['rdata']
        return r

    def read_config(self):
    """ Reads the config from the list of config files"""

        for config_file in self.config_files:
            self.config_files[config_file] = config = {}
            config_parser = ConfigParser.SafeConfigParser()
            try:
                config_parser.read(config_file)
                config_values = config_parser.items("default")    
            except:
                self.die("Error reading config file %s\n" % config_file)

            for var, value in config_values:
                if var == "domain":
                    config['domain'] = value.split(".")
                elif var == "name servers":
                    config['name_servers'] = []
                    split_name_servers = value.split(":")
                    num_split_name_servers = len(split_name_servers)
                    for i in range(0,num_split_name_servers,3):
                        server = split_name_servers[i]
                        ip = split_name_servers[i+1]
                        ttl = int(split_name_servers[i+2])
                        config['name_servers'].append((server.split("."), utils.ipstr2int(ip), ttl))
                elif var == 'source':
                    module_and_args = value.split(":")
                    module = module_and_args[0]
                    args = module_and_args[1:]
                    source_module = __import__(module, {}, {}, [''])
                    source_instance = source_module.Source(*args)
                    config['source'] = source_instance
                elif var == 'filters':
                    config['filters'] = []
                    for module_and_args_str in value.split():
                        module_and_args = module_and_args_str.split(":")
                        module = module_and_args[0]
                        args = module_and_args[1:]
                        filter_module = __import__(module, {}, {}, [''])            
                        filter_instance = filter_module.Filter(*args)
                        config['filters'].append(filter_instance)
                else:
                    self.die("unrecognized parameter in conf file %s: %s\n" % (config_file, var))

            if 'domain' not in config or 'source' not in config:
                self.die("must specify domain name and source in conf file %s\n", config_file)
            sys.stderr.write("read configuration from %s\n" % config_file)

    def reread(self, signum, frame):
    """Used when trapping the signal, usually SIGHUP"""

        self.read_config()
    
    def die(self, msg):
    """Just a msg wrapper"""

        sys.stderr.write(msg)
        sys.exit(-1)


def main():

    usage = '%prog [options] [config_files]\n\nconfig_files = One or more config files, defaults to "pymds.conf"'
    parser = optparse.OptionParser(usage=usage)
    parser.add_option('-p', '--port', dest='port', type=int, default=53,
        help='Port to run the DNS server on (default: 53)')
    parser.add_option('-i', '--ip', dest='ip', default='0.0.0.0',
        help='IP to bind ourselved on to (default: 0.0.0.0)')
    parser.add_option('-d', '--debug', dest='debug', default=False, action='store_true',
        help='Debug mode, this may impact performance since it has to flush on every query')
    (options, filenames) = parser.parse_args()

    config_files = {}
    if not filenames:
        filenames = ['pymds.conf']
    for f in filenames:
        if f in config_files:
            raise Exception("repeated configuration")
        config_files[f] = {}

    sys.stdout.write("%s starting on %s:%d\n" % (sys.argv[0], options.ip, options.port))
    dns = DnsServer(config_files=config_files, listen_port=options.port, listen_host=options.ip)
    dns.set_debug(options.debug)
    signal.signal(signal.SIGHUP, dns.reread)
    for config in config_files.values():
        sys.stdout.write("%s: serving for domain %s\n" % (sys.argv[0], ".".join(config['domain'])))
    sys.stdout.flush()
    sys.stderr.flush()
    dns.serve()

if __name__ == "__main__":
    sys.exit(main())


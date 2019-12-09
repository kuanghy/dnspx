# -*- coding: utf-8 -*-

# Copyright (c) Huoty, All rights reserved
# Author: Huoty <sudohuoty@163.com>

import socket
import logging
import socketserver

import dns.message


log = logging.getLogger(__name__)


class DNSHandler():

    def parse(self, message):
        response = ""
        print("-" * 100)
        print(message)
        print()
        qmsg = dns.message.from_wire(message)
        return response

        try:
            # Parse data as DNS
            d = DNSRecord.parse(data)
            print("-"*100)
            print(d)
            print("-"*100)
        except Exception:
            log.error(f"{self.client_address[0]}: ERROR: invalid DNS request")

        # Only Process DNS Queries
        if QR[d.header.qr] == "QUERY":

            # Gather query parameters
            # NOTE: Do not lowercase qname here, because we want to see
            #       any case request weirdness in the logs.
            qname = str(d.q.qname)

            # Chop off the last period
            if qname[-1] == '.': qname = qname[:-1]

            qtype = QTYPE[d.q.qtype]

            # Find all matching fake DNS records for the query name or get False
            fake_records = dict()

            for record in self.server.nametodns:

                fake_records[record] = self.findnametodns(qname, self.server.nametodns[record])

            # Check if there is a fake record for the current request qtype
            if qtype in fake_records and fake_records[qtype]:

                fake_record = fake_records[qtype]

                # Create a custom response to the query
                response = DNSRecord(DNSHeader(id=d.header.id, bitmap=d.header.bitmap, qr=1, aa=1, ra=1), q=d.q)

                log.info(f"{self.client_address[0]}: cooking the response of type '{qtype}' for {qname} to {fake_record}")

                # IPv6 needs additional work before inclusion:
                if qtype == "AAAA":
                    ipv6_hex_tuple = list(map(int, ip_address(fake_record).packed))
                    response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](ipv6_hex_tuple)))

                elif qtype == "SOA":
                    mname,rname,t1,t2,t3,t4,t5 = fake_record.split(" ")
                    times = tuple([int(t) for t in [t1,t2,t3,t4,t5]])

                    # dnslib doesn't like trailing dots
                    if mname[-1] == ".": mname = mname[:-1]
                    if rname[-1] == ".": rname = rname[:-1]

                    response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](mname,rname,times)))

                elif qtype == "NAPTR":
                    order,preference,flags,service,regexp,replacement = list(map(lambda x: x.encode(), fake_record.split(" ")))
                    order = int(order)
                    preference = int(preference)

                    # dnslib doesn't like trailing dots
                    if replacement[-1] == ".": replacement = replacement[:-1]

                    response.add_answer( RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](order,preference,flags,service,regexp,DNSLabel(replacement))) )

                elif qtype == "SRV":
                    priority, weight, port, target = fake_record.split(" ")
                    priority = int(priority)
                    weight = int(weight)
                    port = int(port)
                    if target[-1] == ".": target = target[:-1]

                    response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](priority, weight, port, target) ))

                elif qtype == "DNSKEY":
                    flags, protocol, algorithm, key = fake_record.split(" ")
                    flags = int(flags)
                    protocol = int(protocol)
                    algorithm = int(algorithm)
                    key = base64.b64decode(("".join(key)).encode('ascii'))

                    response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](flags, protocol, algorithm, key) ))

                elif qtype == "RRSIG":
                    covered, algorithm, labels, orig_ttl, sig_exp, sig_inc, key_tag, name, sig = fake_record.split(" ")
                    covered = getattr(QTYPE,covered) # NOTE: Covered QTYPE
                    algorithm = int(algorithm)
                    labels = int(labels)
                    orig_ttl = int(orig_ttl)
                    sig_exp = int(time.mktime(time.strptime(sig_exp +'GMT',"%Y%m%d%H%M%S%Z")))
                    sig_inc = int(time.mktime(time.strptime(sig_inc +'GMT',"%Y%m%d%H%M%S%Z")))
                    key_tag = int(key_tag)
                    if name[-1] == '.': name = name[:-1]
                    sig = base64.b64decode(("".join(sig)).encode('ascii'))

                    response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](covered, algorithm, labels,orig_ttl, sig_exp, sig_inc, key_tag, name, sig) ))

                else:
                    # dnslib doesn't like trailing dots
                    if fake_record[-1] == ".": fake_record = fake_record[:-1]
                    response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](fake_record)))

                response = response.pack()

            elif qtype == "*" and not None in list(fake_records.values()):
                log.info(f"{self.client_address[0]}: cooking the response of type 'ANY' for {qname} with all known fake records")

                response = DNSRecord(DNSHeader(id=d.header.id, bitmap=d.header.bitmap,qr=1, aa=1, ra=1), q=d.q)

                for qtype,fake_record in list(fake_records.items()):
                    if fake_record:

                        # NOTE: RDMAP is a dictionary map of qtype strings to handling classses
                        # IPv6 needs additional work before inclusion:
                        if qtype == "AAAA":
                            fake_record = list(map(int, ip_address(fake_record).packed))

                        elif qtype == "SOA":
                            mname,rname,t1,t2,t3,t4,t5 = fake_record.split(" ")
                            times = tuple([int(t) for t in [t1,t2,t3,t4,t5]])

                            # dnslib doesn't like trailing dots
                            if mname[-1] == ".": mname = mname[:-1]
                            if rname[-1] == ".": rname = rname[:-1]

                            response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](mname,rname,times)))

                        elif qtype == "NAPTR":
                            order,preference,flags,service,regexp,replacement = fake_record.split(" ")
                            order = int(order)
                            preference = int(preference)

                            # dnslib doesn't like trailing dots
                            if replacement and replacement[-1] == ".": replacement = replacement[:-1]

                            response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](order,preference,flags,service,regexp,replacement)))

                        elif qtype == "SRV":
                            priority, weight, port, target = fake_record.split(" ")
                            priority = int(priority)
                            weight = int(weight)
                            port = int(port)
                            if target[-1] == ".": target = target[:-1]

                            response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](priority, weight, port, target) ))

                        elif qtype == "DNSKEY":
                            flags, protocol, algorithm, key = fake_record.split(" ")
                            flags = int(flags)
                            protocol = int(protocol)
                            algorithm = int(algorithm)
                            key = base64.b64decode(("".join(key)).encode('ascii'))

                            response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](flags, protocol, algorithm, key) ))

                        elif qtype == "RRSIG":
                            covered, algorithm, labels, orig_ttl, sig_exp, sig_inc, key_tag, name, sig = fake_record.split(" ")
                            covered = getattr(QTYPE,covered) # NOTE: Covered QTYPE
                            algorithm = int(algorithm)
                            labels = int(labels)
                            orig_ttl = int(orig_ttl)
                            sig_exp = int(time.mktime(time.strptime(sig_exp +'GMT',"%Y%m%d%H%M%S%Z")))
                            sig_inc = int(time.mktime(time.strptime(sig_inc +'GMT',"%Y%m%d%H%M%S%Z")))
                            key_tag = int(key_tag)
                            if name[-1] == '.': name = name[:-1]
                            sig = base64.b64decode(("".join(sig)).encode('ascii'))

                            response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](covered, algorithm, labels,orig_ttl, sig_exp, sig_inc, key_tag, name, sig) ))

                        else:
                            # dnslib doesn't like trailing dots
                            if fake_record[-1] == ".": fake_record = fake_record[:-1]
                            response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](fake_record)))

                response = response.pack()

            # Proxy the request
            else:
                log.info(f"{self.client_address[0]}: proxying the response of type '{qtype}' for {qname}")

                nameserver_tuple = random.choice(self.server.nameservers).split('#')
                response = self.proxyrequest(data, *nameserver_tuple)

        return response


class UDPHandler(DNSHandler, socketserver.BaseRequestHandler):

    def handle(self):
        (data, socket) = self.request
        response = self.parse(data)

        if response:
            socket.sendto(response, self.client_address)


class TCPHandler(DNSHandler, socketserver.BaseRequestHandler):

    def handle(self):
        data = self.request.recv(1024)

        # Remove the addition "length" parameter used in the
        # TCP DNS protocol
        data = data[2:]
        response = self.parse(data)

        if response:
            # Calculate and add the additional "length" parameter
            # used in TCP DNS protocol
            length = binascii.unhexlify("%04x" % len(response))
            self.request.sendall(length + response)


class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):

    # Override default value
    allow_reuse_address = True

    # Override SocketServer.TCPServer to add extra parameters
    def __init__(self, server_address, RequestHandlerClass, nametodns, nameservers, ipv6, log):
        self.nametodns = nametodns
        self.nameservers = nameservers
        self.ipv6 = ipv6
        self.address_family = socket.AF_INET6 if self.ipv6 else socket.AF_INET
        self.log = log

        socketserver.TCPServer.__init__(self, server_address, RequestHandlerClass)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):

    pass


class DNSProxyServer(object):

    def run(object):
        nametodns = None
        nameservers = ["119.29.29.29"]
        ipv6 = True
        server = ThreadedUDPServer(("127.0.0.1", 53), UDPHandler, nametodns, nameservers, ipv6, log)
        server.serve_forever()

import dpkt
import socket
import binascii
import sys
 
pcapFileName = 'test2.pcap'

def rfc1918(ip):
  try:
    octets = map(int, ip.split('.'))
  except:
    return False
 
  if len([x for x in octets if 0<=x<=255]) != 4:
    return False
 
  if octets[0] == 10:
    return True
  elif octets[0] == 172 and octets[1] in range(16,32):
    return True
  elif octets[0] == 192 and octets[1] == 168:
    return True
  else:
    return False

def openPcap(filename):
  f = open(fileName, 'rb')
  pcap = dpkt.pcap.Reader(f)

def closePcap(handle):
  handle.close()

def parseIPs():
  pass
def parseDomains():
  pass

  
uniqueHosts = set([])
uniqueIPs = set([])
count =0
for ts, buf in pcap:
  eth = dpkt.ethernet.Ethernet(buf)
  try:
    ip = eth.data
    src = socket.inet_ntoa(ip.src)
    dst = socket.inet_ntoa(ip.dst)
    uniqueIPs.add(src)
    uniqueIPs.add(dst)
    count += 2
    #print "src:",src,"-- dst:",dst
  except:
    pass
 
 
  try:
    ip = eth.data
    udp = ip.data
    dns = dpkt.dns.DNS(udp.data)
    name = dns.qd[0].name
    print dns.qd
    if '.' in name:
      uniqueHosts.add(name)
    
  except:
    pass
 
print "Count",len(uniqueIPs),"out of", count
 
y = 0
nonRFCips = set([])
for x in uniqueIPs:
  if rfc1918(x):
    pass
  else:
    nonRFCips.add(x)
    y +=1
# print 'Non RFC1918 IPs:', y
 
# print 'uniqueHosts:', len(uniqueHosts)
# for x in nonRFCips:
#   print x
#   if x == '65.121.209.16':
#     print 'found it'
 
 
 
f.close()
 

 

f = open(pcapFileName, 'rb')
pcap = dpkt.pcap.Reader(f)
 
for ts, buf in pcap:
 try: 
  eth = dpkt.ethernet.Ethernet(buf)
 except: 
  continue

 if eth.type != 2048: 
  continue

 try: 
  ip = eth.data
 except: 
  continue
 if ip.p != 17: 
  continue

 try: 
  udp = ip.data
 except: 
  continue

 if udp.sport != 53 and udp.dport != 53: 
  continue

 try: 
  dns = dpkt.dns.DNS(udp.data)
 except: 
  continue

 if dns.qr != dpkt.dns.DNS_R: 
  continue
 if dns.opcode != dpkt.dns.DNS_QUERY: 
  continue
 if dns.rcode != dpkt.dns.DNS_RCODE_NOERR: 
  continue
 if len(dns.an) < 1: 
  continue

 for answer in dns.an:
   if answer.type == 5:
     #cname = dns & response = dns
     print "CNAME request", answer.name, "\tresponse", answer.cname
   elif answer.type == 1:
     #a = dns & response = ip
     print "A request", answer.name, "\tresponse", socket.inet_ntoa(answer.rdata)
   elif answer.type == 12:
     # i don't know
     print "PTR request", answer.name, "\tresponse", answer.ptrname 
 
 
 
# import socket
 
# def validate_ip(ip):
#     try:
#         socket.inet_pton(socket.AF_INET, ip)
#     except socket.error:
#         try:
#             socket.inet_pton(socket.AF_INET6, ip)
#         except socket.error:
#             return False
#     return True
 
# print validate_ip("500.500.500.500")
# print validate_ip("198.51.100.1")
# print validate_ip("2001:0db8:0000:0000:0000:ff00:0042:8329")
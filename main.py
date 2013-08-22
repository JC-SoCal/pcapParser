import dpkt
import socket
import binascii
import sys
 
pcapFileName = 'test2.pcap'

def isIPRFC1918(ip):
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

def openPCAP(filename):
  f = open(filename, 'rb')
  return dpkt.pcap.Reader(f)

def closePCAP(handle):
  handle.close()

def ethFrametoIPs(eth):
  IPs = []
  try:
    ip = eth.data
    try:
      IPs.append(socket.inet_ntoa(ip.src))
    except: pass
    try:
      IPs.append(socket.inet_ntoa(ip.dst))
    except: pass
  except: pass
  return IPs

def ethFrametoDNS(eth):
  pass  

# def ethFrametoDNS(eth):
#   pass  
 
# uniqueIPs = set([])
# uniqueIP(eth):
#   for ip in ethFrametoIPs(eth):
#     uniqueIPs.add(ip)
 
# uniqueHosts = set([])
# uniqueHost(eth):
#  # BLAH
 
# def iteratePCAP(pcap,callbacks=[]):

def iteratePCAP(pcap):
  uniqueHosts = set([])
  uniqueIPs = set([])

  for ts, buff in pcap:
    try:
      eth = dpkt.ethernet.Ethernet(buff)
      
      try:
        for ip in ethFrametoIPs(eth):
          uniqueIPs.add(ip)
        except: pass

    except: pass

    #DNS carving
    try:
      print 6
      ip = eth.data
      if eth.type != 2048: continue
      if ip.p != 17: continue
      udp = ip.data
      if udp.sport != 53 and udp.dport != 53: continue
      dns = dpkt.dns.DNS(udp.data)
      if dns.qr != dpkt.dns.DNS_R: continue
      if dns.opcode != dpkt.dns.DNS_QUERY: continue
      if dns.rcode != dpkt.dns.DNS_RCODE_NOERR: continue
      if len(dns.an) < 1: continue

      for answer in dns.an:
        print 7
        uniqueHosts.add(answer.name)
        if answer.type == 5:
          #cname = dns & response = dns
          uniqueHosts.add(answer.cname)
          #print "CNAME request", answer.name, "\tresponse", answer.cname
        elif answer.type == 1:
          pass
          #uniqueIPs.add(socket.inet_ntoa(answer.rdata))
          #a = dns & response = ip
          #print "A request", answer.name, "\tresponse", socket.inet_ntoa(answer.rdata)
        elif answer.type == 12:
          # i don't know
          uniqueHosts.add(answer.ptrname)
          #print "PTR request", answer.name, "\tresponse", answer.ptrname 
    except: continue
    return [uniqueIPs, uniqueHosts]


 

pcap = openPCAP(pcapFileName)
print iteratePCAP(pcap)


# print "Count",len(uniqueIPs),"out of", count
 
# y = 0
# nonRFCips = set([])
# for x in uniqueIPs:
#   if rfc1918(x):
#     pass
#   else:
#     nonRFCips.add(x)
#     y +=1
# print 'Non RFC1918 IPs:', y
 
# print 'uniqueHosts:', len(uniqueHosts)
# for x in nonRFCips:
#   print x
#   if x == '65.121.209.16':
#     print 'found it'
 
 
 
# f.close()
 

 

# f = open(pcapFileName, 'rb')
# pcap = dpkt.pcap.Reader(f)
 
# for ts, buf in pcap:
#  try: 
#   eth = dpkt.ethernet.Ethernet(buf)
#  except: 
#   continue

#  if eth.type != 2048: 
#   continue

#  try: 
#   ip = eth.data
#  except: 
#   continue
#  if ip.p != 17: 
#   continue

#  try: 
#   udp = ip.data
#  except: 
#   continue

#  if udp.sport != 53 and udp.dport != 53: 
#   continue

#  try: 
#   dns = dpkt.dns.DNS(udp.data)
#  except: 
#   continue

#  if dns.qr != dpkt.dns.DNS_R: 
#   continue
#  if dns.opcode != dpkt.dns.DNS_QUERY: 
#   continue
#  if dns.rcode != dpkt.dns.DNS_RCODE_NOERR: 
#   continue
#  if len(dns.an) < 1: 
#   continue

#  for answer in dns.an:
#    if answer.type == 5:
#      #cname = dns & response = dns
#      print "CNAME request", answer.name, "\tresponse", answer.cname
#    elif answer.type == 1:
#      #a = dns & response = ip
#      print "A request", answer.name, "\tresponse", socket.inet_ntoa(answer.rdata)
#    elif answer.type == 12:
#      # i don't know
#      print "PTR request", answer.name, "\tresponse", answer.ptrname 
 
 
 
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
import dpkt
import socket
import binascii
import sys
 
pcapFileName = 'test2.pcap'

def filterRFC1918(ip):
  try:
    octets = map(int, ip.split('.'))
  except:
    return False

  if len([x for x in octets if 0<=x<=255]) != 4: return False

  if octets[0] == 10: return True
  elif octets[0] == 172 and octets[1] in range(16,32): return True
  elif octets[0] == 192 and octets[1] == 168: return True
  else: return False

def filterIP(data):


def openPCAP(filename):
  f = open(filename, 'rb')
  return dpkt.pcap.Reader(f)

def closePCAP(handle):
  handle.close()

def ethFrameToIPs(eth):  
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

def ethFrameToDomains(eth):
  data = []
  try:
    ip = eth.data
    if eth.type == 2048:
      if ip.p == 17:
        udp = ip.data
        if udp.sport == 53 or udp.dport == 53: 
          dns = dpkt.dns.DNS(udp.data)
          if dns.qr == dpkt.dns.DNS_R: 
            if dns.opcode == dpkt.dns.DNS_QUERY: 
              if dns.rcode == dpkt.dns.DNS_RCODE_NOERR: 
                if len(dns.an) > 0: 
                  for answer in dns.an:
                    data.append(answer.name)
                    if answer.type == 5: data.append(answer.cname)
                    elif answer.type == 1: data.append(socket.inet_ntoa(answer.rdata))
                    elif answer.type == 12: data.append(answer.ptrname)
  except: 
    pass
  return data
 
def iteratePCAP(pcap,callbacks=[]):
  data = set([])
  for ts, buff in pcap:
    try:
      eth = dpkt.ethernet.Ethernet(buff)
      
      for callback in callbacks:
        for item in callback(eth):
          data.add(item)
    except: 
      pass

  return data






pcap = openPCAP(pcapFileName)
x = iteratePCAP(pcap,[ethFrameToIPs,ethFrameToDomains])
print len(x)


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
 
 
 

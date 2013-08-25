import dpkt
import socket
import binascii
import sys

 
pcapFileName = 'test2.pcap'

def f_RFC1918(ip):
  try:
    octets = map(int, ip.split('.'))
  except:
    return False

  if len([x for x in octets if 0<=x<=255]) != 4: return False

  if octets[0] == 10: return True
  elif octets[0] == 172 and octets[1] in range(16,32): return True
  elif octets[0] == 192 and octets[1] == 168: return True
  else: return False

def f_IPv4(ip):
  try:
    socket.inet_aton(ip)
  except socket.error:
    return False
  return True

def f_Domains(name):
  pass

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


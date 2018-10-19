#!/usr/bin/env python2

import os
import sys
import datetime
import time
import re
import pynfdump
from IPy import IP

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxlclient.callbacks import EventCallback
from dxlclient.message import Message, Event
from common import *

clientPath = os.path.dirname(os.path.realpath(__file__))

alertqueue = []

def lookupIP(ip, dxlif):
  try:
    v = IP(ip).version()
  except:
    return
  if v == 4 or v == 6:
    try:
      print("Looking up: %s" % ip)
      d = pynfdump.Dumper("/data/nfsen/profiles-data", profile='live', sources=['local'])
      d.set_where(start="2017-11-16 13:10", end=time.strftime("%Y-%m-%d %H:%M"))
      records = d.search("src ip %s" % ip, aggregate=['dstip'])
      tgt = []
      for r in records:
        if r['dstip'] not in tgt:
          tgt.append(r['dstip'])
      if len(tgt) > 0:
        for t in tgt:
          evtstr = '/feed/compromised/ipv' + str(IP(t).version())
          evt = Event(evtstr)
          evt.payload = str(t).encode()
          dxlif.send_event(evt)
          print("Event emitted topic: %s content: %s" % (evtstr, str(t)))

    except Exception as e:
      print("Exception while processing %s: %s" % (ip, str(e)))
      return

class netflowV4CB(EventCallback):

  def __init__(self, dxlif=None):
    super(netflowV4CB, self).__init__()
    self.dxlif = dxlif
    print("INIT NFv4")

  def on_event(self, event):
    lookupIP(re.sub(r"(?m)[\x00\n\r]+", "", event.payload.decode()), self.dxlif)


class netflowV6CB(EventCallback):

  def __init__(self, dxlif=None):
    super(netflowV6CB, self).__init__()
    self.dxlif = dxlif
    print("INIT NFv6")

  def on_event(self, event):
    lookupIP(re.sub(r"(?m)[\x00\n\r]+", "", event.payload.decode()), self.dxlif)


if __name__ == '__main__':

  config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

  with DxlClient(config) as client:      
    client.connect()
    client.add_event_callback("/feed/bad/ipv4", netflowV4CB(client))
    client.add_event_callback("/feed/bad/ipv6", netflowV6CB(client))

    try:
      while 1:
        time.sleep(0.1)
    except (KeyboardInterrupt, EOFError) as e:
      sys.exit(0)

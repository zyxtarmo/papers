#!/usr/bin/env python2

import os
import sys
import datetime
import time
import re
import iptc
from IPy import IP

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxlclient.callbacks import EventCallback
from common import *

v4iplist = []
v6iplist = []

def dropIPv4(ip4):
  try:
    v = IP(ip4).version()
  except:
    return
  if ip4 not in v4iplist and v == 4:
    try:
      chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
      rule = iptc.Rule()
      rule.in_interface = "eth+"
      rule.src = ip4
      rule.target = iptc.Target(rule, "DROP")
      chain.insert_rule(rule)
      v4iplist.append(ip4)
    except Exception as e:
      print("OpenDXL.dropIPv4.Exception(%s): %s" % (ip4, str(e)))

def dropIPv6(ip6):
  try:
    v = IP(ip6).version()
  except:
    return
  if ip6 not in v6iplist and v == 6:
    try:
      chain = iptc.Chain(iptc.Table6(iptc.Table6.FILTER), "INPUT")
      rule = iptc.Rule6()
      rule.in_interface = "eth+"
      rule.src = ip6
      rule.target = iptc.Target(rule, "DROP")
      chain.insert_rule(rule)
      v6iplist.append(ip6)
    except Exception as e:
      print("OpenDXL.dropIPv6.Exception(%s): %s" % (ip6, str(e)))

class firewallV4CB(EventCallback):

  def on_event(self, event):
    dropIPv4(re.sub(r"(?m)[\x00\n\r]+", "", event.payload.decode()))

class firewallV6CB(EventCallback):

  def on_event(self, event):
    dropIPv6(re.sub(r"(?m)[\x00\n\r]+", "", event.payload.decode()))

if __name__ == '__main__':

  config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

  with DxlClient(config) as client:      
    client.connect()
    client.add_event_callback("/feed/bad/ipv4", firewallV4CB())
    client.add_event_callback("/feed/bad/ipv6", firewallV6CB())

    try:
      while 1:
        time.sleep(0.1)
    except (KeyboardInterrupt, EOFError, SystemExit) as e:
      sys.exit(0)

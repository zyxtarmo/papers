
#!/usr/bin/env python2

import os
import sys
import datetime
import time
import virtualbox
import re
from subprocess import check_call

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxlclient.callbacks import EventCallback
from common import *


ip_bindings = {
        '192.168.56.100': 'User Workstation', 
        '12.12.12.12': 'nonexistent'
    }

def rollback(ip):
    vm = None
    if ip in ip_bindings.keys():
        try:
            print("vboxmanage controlvm '%s' acpipowerbutton" % ip_bindings[ip])
            check_call(["vboxmanage", "controlvm", ip_bindings[ip], "acpipowerbutton"])
            time.sleep(10)
            print("vboxmanage snapshot '%s' restore 'Configured WS'" % ip_bindings[ip])
            check_call(["vboxmanage", "snapshot", ip_bindings[ip], "restore", "Configured WS"])
            print("vboxmanage startvm '%s'" % ip_bindings[ip])
            check_call(["vboxmanage", "startvm", ip_bindings[ip]])
            # ... or ...
            # vm = self.vbox.find_machine(ip_bindings[ip])
            # session = vm.create_session()
            # snap = vm.find_snapshot('Configured WS')
            # progress = session.console.power_down()
            # progress.wait_for_completion(10)
            # console = session.console
            # console.restore_snapshot(snap)
        except Exception as e:
            print("Machine '%s' for ip %s Error: %s" % (ip_bindings[ip], ip, str(e)))
    else:
        print("Machine for ip %s could not be found" % (ip))

class vmCB(EventCallback):

  def on_event(self, event):
    rollback(re.sub(r"(?m)[\x00\n\r]+", "", event.payload.decode()))


if __name__ == '__main__':

  config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

  with DxlClient(config) as client:
    client.connect()
    client.add_event_callback("/feed/compromised/ipv4", vmCB())
    client.add_event_callback("/feed/compromised/ipv6", vmCB())

    try:
      while 1:
        time.sleep(0.1)
    except (KeyboardInterrupt, EOFError) as e:
      sys.exit(0)

import json
import os
import sys
import time

# Import our sibling src folder into the path
sys.path.append(os.path.abspath('src'))

# Classes to test - manually imported from sibling folder
import dtCrowdstrike
from dtCrowdstrike.client import CrowdstrikeClient

nix_sample_script = '#!/bin/sh\n[ -e "ADG-sample.out" ] && rm "ADG-sample.out"\nchmod u+x ./ADG-Sample.sh\n./ADG-Sample.sh\n[ -e "ADG-Sample.sh" ] && rm "ADG-Sample.sh"'
nix_clean_sample_script = '#!/bin/sh\n[ -e "ADG-sample.out" ] && rm "ADG-sample.out"'

nix_initial_script = '#!/bin/sh\n[ -e "ADG-initial.out" ] && rm "ADG-initial.out"\nchmod u+x ./ADG-Initial.sh\n./ADG-Initial.sh\n[ -e "ADG-Initial.sh" ] && rm "ADG-Initial.sh"'
nix_clean_initial_script = '#!/bin/sh\n[ -e "ADG-initial.out" ] && rm "ADG-initial.out"'

print(f"{dtCrowdstrike.title()} - Version: {dtCrowdstrike.version()}")

with CrowdstrikeClient(client_secret=os.environ['CLIENT_SECRET'], client_id=os.environ['CLIENT_ID']) as client:
    details = []
    # client.get_host("ARTSIMLGC01.sbsms.sbs.com.au").get_host_details(extended=True)
    # _filter = f"(last_seen:>='now-720h' + last_seen:<'now') + hostname:*!'L-*'"
    hosts = list(client.get_online_servers("720"))
    # client.get_utilities().bulk_exporter().export_hosts_as_excel(hosts, excel_file="hosts.xlsx")
    for host in hosts:
        print(host.get_hostname())
        details.append(host.get_host_details(extended=True))

    with open('out.json', 'w') as jout:
        json.dump(details, jout, indent=4)
    # client.get_utilities().bulk_exporter().export_hosts_as_excel(hosts, excel_file="servers.xlsx")
import json
import os
import sys
import time

# Import our sibling src folder into the path
sys.path.append(os.path.abspath('src'))

# Classes to test - manually imported from sibling folder
import dtCrowdstrike
from dtCrowdstrike import CrowdstrikeClient

sample_script = '#!/bin/sh\n[ -e "ADG-sample.out" ] && rm "ADG-sample.out"\nchmod u+x ./ADG-Sample.sh\n./ADG-Sample.sh\n[ -e "ADG-Sample.sh" ] && rm "ADG-Sample.sh"'
clean_sample_script = '#!/bin/sh\n[ -e "ADG-sample.out" ] && rm "ADG-sample.out"'

initial_script = '#!/bin/sh\n[ -e "ADG-initial.out" ] && rm "ADG-initial.out"\nchmod u+x ./ADG-Initial.sh\n./ADG-Initial.sh\n[ -e "ADG-Initial.sh" ] && rm "ADG-Initial.sh"'
clean_initial_script = '#!/bin/sh\n[ -e "ADG-initial.out" ] && rm "ADG-initial.out"'

print(f"{dtCrowdstrike.title()} - Version: {dtCrowdstrike.version()}")
with CrowdstrikeClient(client_secret=os.environ['CLIENT_SECRET'], client_id=os.environ['CLIENT_ID']) as client:
    hosts = []
    for host in client.find_hosts('machine_domain:"AD.SBSBMI.DEV"'):
        hosts.append(host)
    client.get_utilities().bulk_exporter().export_hosts_as_json(host_producer=hosts)
    # group = client.create_dynamic_host_group(name="AD.SBSBMI.DEV", description="BMI AWS Domain Instance Machines", rule='machine_domain:"AD.SBSBMI.DEV"')
    # print(group)
    # hosts = []
    # for host in client.find_hosts('machine_domain:"AD.SBSBMI.DEV"'):
    #     hosts.append(host)
    #
    # with client.get_utilities().bulk_host_operations(hosts) as bulk_host_operations:
    #     bulk_host_operations.run_command(command='runscript', parameters='-Raw="del C:/ADG-sample.cmd"', timeout=3600,
    #                                      encapsulate="")
    #     bulk_host_operations.run_command(command='runscript', parameters='-Raw="del C:/ADG-sample.out"', timeout=3600,
    #                                      encapsulate="")
    #     bulk_host_operations.run_command(command='runscript', parameters='-Raw="del C:/ADG-initial.cmd"', timeout=3600,
    #                                      encapsulate="")
    #     bulk_host_operations.run_command(command='runscript', parameters='-Raw="del C:/ADG-initial.out"', timeout=3600,
    #                                      encapsulate="")
    #     print(bulk_host_operations.run_command('put', 'ADG-sample.cmd'))
    #     bulk_host_operations.run_command(command='runscript', parameters='-Raw="C:/ADG-sample.cmd"', timeout=3600, encapsulate="")
    #     while bulk_host_operations.file_exists('C:/ADG-sample.out.running'):
    #         time.sleep(1)
    #     for entry in bulk_host_operations.get_file(filename='ADG-sample.out'):
    #         with open(f"{entry['aid']}-sample.out", "wb") as out_adg:
    #             out_adg.write(entry['content'])
    #     bulk_host_operations.run_command(command='runscript', parameters='-Raw="del C:/ADG-sample.cmd"', timeout=3600,
    #                                      encapsulate="")
    #     bulk_host_operations.run_command(command='runscript', parameters='-Raw="del C:/ADG-sample.out"', timeout=3600,
    #                                      encapsulate="")
    #     bulk_host_operations.run_command(command='runscript', parameters='-Raw="del C:/ADG-initial.cmd"', timeout=3600,
    #                                      encapsulate="")
    #     bulk_host_operations.run_command(command='runscript', parameters='-Raw="del C:/ADG-initial.out"', timeout=3600,
    #                                      encapsulate="")
    # host = client.get_host("SBSPRUTIL01")
    # print(host.get_summary_host_details())
    # with host.get_realtime_response() as rtr:
    #     print(rtr.run_command("put", "ADG-Initial.sh", encapsulate=""))
    #     print(rtr.runscript(initial_script))
    #     print(rtr.get_file("./ADG-initial.out"))
    #     print(rtr.runscript(clean_initial_script))
    #     print(rtr.file_exists("./ADG-initial.out"))





    # for host in client.get_online_windows_servers():
    #     print(host.get_host_details)
    # for detect in client.get_detections():
    #     print(detect.get_summary())
    #     print(detect.get_host().get_hostname())
    #     for d in detect.get_host().get_detections():
    #         print(d.get_host().get_hostname() == detect.get_host().get_hostname())
    # for host in client.get_online_windows_servers():
    #
    #     hostname = host.get_hostname()
    #     with host.get_realtime_response() as rtr:
    #         print(rtr.run_command(command="ps"))
        # existing_data = []
        # if os.path.exists(f"{hostname}.json"):
        #     with open(f"{hostname}.json", "r") as cdata:
        #         existing_data = json.load(cdata)
        #
        # for rec in counter:
        #     existing_data.append(rec)
        #
        # with open(f"{hostname}.json", "w") as cdata:
        #     json.dump(existing_data, cdata, indent=4)
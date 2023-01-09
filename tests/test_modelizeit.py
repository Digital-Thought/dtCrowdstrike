import json
import os
import sys
import time

from multiprocessing import Process, Queue
from datetime import datetime

# Import our sibling src folder into the path
sys.path.append(os.path.abspath('src'))

# Classes to test - manually imported from sibling folder
import dtCrowdstrike
from dtCrowdstrike import CrowdstrikeClient

nix_sample_script = '#!/bin/sh\n[ -e "ADG-sample.out" ] && rm "ADG-sample.out"\nchmod u+x ./ADG-Sample.sh\n./ADG-Sample.sh\n[ -e "ADG-Sample.sh" ] && rm "ADG-Sample.sh"'
nix_clean_sample_script = '#!/bin/sh\n[ -e "ADG-sample.out" ] && rm "ADG-sample.out"'

nix_initial_script = '#!/bin/sh\n[ -e "ADG-initial.out" ] && rm "ADG-initial.out"\nchmod u+x ./ADG-Initial.sh\n./ADG-Initial.sh\n[ -e "ADG-Initial.sh" ] && rm "ADG-Initial.sh"'
nix_clean_initial_script = '#!/bin/sh\n[ -e "ADG-initial.out" ] && rm "ADG-initial.out"'

custom_targets = ["SYDW8019", "SYDMEDIAFLEX", "SYDVMW8071", "SVWDRDB01"]

nix_count = 12
batch_size = 10
threads = 10
all_reader_procs = list()
frequency = 1
scan_period = 7
store_directory = "./adg"
batch_count = 0


def aid_record(aid):
    os.makedirs(f'{store_directory}/{aid[:1]}/{aid[:3]}', exist_ok=True)
    return f'{store_directory}/{aid[:1]}/{aid[:3]}/{aid}.json'


def aid_out_file(aid):
    os.makedirs(f'{store_directory}/{aid[:1]}/{aid[:3]}', exist_ok=True)
    return f'{store_directory}/{aid[:1]}/{aid[:3]}/{aid}.out'


def build_batches(hosts, batches):
    global batch_count
    nix_hosts = []
    win_hosts = []
    existing_nix_hosts = []
    existing_win_hosts = []
    for host in hosts:
        aid = host.aid

        if host.is_windows() and os.path.exists(aid_record(aid)):  # and os.path.exists(aid_out(aid)):
            existing_win_hosts.append(host.aid)
        elif host.is_linux() and os.path.exists(aid_record(aid)):  # and os.path.exists(aid_out(aid)):
            existing_nix_hosts.append(host.aid)
        elif host.is_windows():
            win_hosts.append(host.aid)
        elif host.is_linux():
            nix_hosts.append(host.aid)

        if len(nix_hosts) == batch_size:
            batches.put({"type": "nix", "hosts": list(nix_hosts), "last_scan": None, "existing": False})
            batch_count += 1
            nix_hosts.clear()

        if len(win_hosts) == batch_size:
            batches.put({"type": "win", "hosts": list(win_hosts), "last_scan": None, "existing": False})
            batch_count += 1
            win_hosts.clear()

        if len(existing_nix_hosts) == batch_size:
            batches.put({"type": "nix", "hosts": list(existing_nix_hosts), "last_scan": None, "existing": True})
            batch_count += 1
            existing_nix_hosts.clear()

        if len(existing_win_hosts) == batch_size:
            batches.put({"type": "win", "hosts": list(existing_win_hosts), "last_scan": None, "existing": True})
            batch_count += 1
            existing_win_hosts.clear()

    if len(nix_hosts) > 0:
        batches.put({"type": "nix", "hosts": list(nix_hosts), "last_scan": None, "existing": False})
        batch_count += 1

    if len(win_hosts) > 0:
        batches.put({"type": "win", "hosts": list(win_hosts), "last_scan": None, "existing": False})
        batch_count += 1

    if len(existing_nix_hosts) > 0:
        batches.put({"type": "nix", "hosts": list(existing_nix_hosts), "last_scan": None, "existing": True})
        batch_count += 1

    if len(existing_win_hosts) > 0:
        batches.put({"type": "win", "hosts": list(existing_win_hosts), "last_scan": None, "existing": True})
        batch_count += 1


def build_processor(queue):
    with CrowdstrikeClient(client_secret=os.environ['CLIENT_SECRET'], client_id=os.environ['CLIENT_ID']) as client:
        target_hosts = list(client.find_hosts(query='machine_domain:"AD.SBSBMI.DEV"'))
        for custom_target in custom_targets:
            target_hosts.append(client.get_host(custom_target))

        current_count = 0
        for nix_target in list(client.get_linux_hosts()):
            target_hosts.append(nix_target)
            current_count += 1
            if current_count == nix_count:
                break

        build_batches(target_hosts, queue)
        print(f'Number of batches: {batch_count}')


def process_existing_target_hosts(targets, os_type):
    print(f'Processing Existing {len(targets)} hosts')
    for entry in targets:
        entry['scan_count'] += 1

        with open(aid_record(entry['aid']), 'w') as aid_out:
            json.dump(entry, aid_out, indent=4)


def strip_hosts(orighosts, aids):
    if len(aids) == 0:
        return list(orighosts)
    new_hosts = []

    for host in orighosts:
        if host.aid not in aids:
            print(host.aid)
            new_hosts.append(host)

    return new_hosts


def process_new_target_hosts(targets, os_type, current_datetime, batches):
    print(f'[{os_type}] Processing New {len(targets)} hosts')
    script_command = None
    put_command = None
    pre_post_script_command1 = None
    pre_post_script_command2 = None
    running_file = None
    get_file = None

    if os_type == "nix":
        script_command = '#!/bin/sh\n[ -e "ADG-initial.out" ] && rm "ADG-initial.out"\nchmod u+x ./ADG-Initial.sh\n./ADG-Initial.sh\n[ -e "ADG-Initial.sh" ] && rm "ADG-Initial.sh"'
        put_command = 'ADG-Initial.sh'
        pre_post_script_command1 = '#!/bin/sh\n[ -e "ADG-initial.out" ] && rm "ADG-initial.out"'
        pre_post_script_command2 = '#!/bin/sh\n[ -e "ADG-Initial.sh" ] && rm "ADG-Initial.sh"'
        running_file = '/ADG-initial.out.running'
        get_file = 'ADG-initial.out'
    elif os_type == "win":
        script_command = "C:/ADG-initial.cmd"
        put_command = "ADG-initial.cmd"
        pre_post_script_command1 = "del C:/ADG-initial.out"
        pre_post_script_command2 = "del C:/ADG-initial.cmd"
        running_file = 'C:/adg-initial.out.running'
        get_file = 'ADG-initial.out'

    with CrowdstrikeClient(client_secret=os.environ['CLIENT_SECRET'], client_id=os.environ['CLIENT_ID']) as client:
        hosts = []
        errors = []
        new_hosts = []
        for entry in targets:
            hosts.append(client.get_host_by_id(entry['aid']))
        with client.get_utilities().bulk_host_operations(hosts) as bulk_host_operations:
            for resp in bulk_host_operations.run_command(command='runscript', parameters=f'-Raw="{pre_post_script_command1}"',
                                                         timeout=3600, encapsulate=""):
                if resp.error:
                    errors.append(resp.aid)
            print(f"[{os_type}] Post Script 1 Command had {len(errors)} Errors")
            errors.clear()

            for resp in bulk_host_operations.run_command(command='runscript', parameters=f'-Raw="{pre_post_script_command2}"',
                                                         timeout=3600, encapsulate=""):
                if resp.error:
                    errors.append(resp.aid)
            print(f"[{os_type}] Post Script 2 Command had {len(errors)} Errors")
            errors.clear()

            for resp in bulk_host_operations.run_command('put', put_command):
                if resp.error:
                    errors.append(resp.aid)

            for host in hosts:
                if host.aid not in errors:
                    new_hosts.append(host)

            print(f"[{os_type}] Put Command had {len(errors)} Errors. Hosts to continue: {len(new_hosts)} of original {len(hosts)}")
            errors.clear()
        if len(new_hosts) > 0:
            with client.get_utilities().bulk_host_operations(new_hosts) as bulk_host_operations:
                for resp in bulk_host_operations.run_command(command='runscript', parameters=f'-Raw="{script_command}"',
                                                             timeout=3600, encapsulate=""):
                    if resp.error:
                        errors.append(resp.aid)

                print(f"[{os_type}] Script Command had {len(errors)} Errors")
                errors.clear()
                while bulk_host_operations.file_exists(running_file):
                    time.sleep(1)

                for entry in bulk_host_operations.get_file(filename=get_file):
                    with open(aid_out_file(entry.aid), "wb") as out_adg:
                        out_adg.write(entry.content)

                for resp in bulk_host_operations.run_command(command='runscript', parameters=f'-Raw="{pre_post_script_command1}"',
                                                             timeout=3600, encapsulate=""):
                    if resp.error:
                        errors.append(resp.aid)
                print(f"[{os_type}] Post Script 1 Command had {len(errors)} Errors")
                errors.clear()

                for resp in bulk_host_operations.run_command(command='runscript', parameters=f'-Raw="{pre_post_script_command2}"',
                                                             timeout=3600, encapsulate=""):
                    if resp.error:
                        errors.append(resp.aid)
                print(f"[{os_type}] Post Script 2 Command had {len(errors)} Errors")
                errors.clear()

        for entry in targets:
            if os.path.exists(aid_out_file(entry['aid'])):
                entry['scan_count'] += 1

                with open(aid_record(entry['aid']), 'w') as aid_out:
                    json.dump(entry, aid_out, indent=4)

    existing = []
    new = []
    for entry in targets:
        if os.path.exists(aid_record(entry['aid'])):
            existing.append(entry['aid'])
        else:
            new.append(entry['aid'])

    print(f'Initial scan failed for {len(new)}')
    print(f'Initial scan successful for {len(existing)}')
    if len(new) > 0:
        batches.put({"type": os_type, "hosts": list(new), "last_scan": None, "existing": False})
    if len(existing) > 0:
        batches.put({"type": os_type, "hosts": list(existing), "last_scan": current_datetime, "existing": True})


def queue_processor(batches):
    print(f"Running Queue Processing")
    while True:
        entry = batches.get()

        target_hosts = []
        current_datetime = datetime.now()
        if not entry["last_scan"] or (((current_datetime - entry["last_scan"]).seconds) % 3600) / 60 >= frequency:
            entry["last_scan"] = current_datetime
            for aid in entry['hosts']:
                if entry["existing"]:
                    with open(aid_record(aid), 'r') as in_aid:
                        aid_data = json.load(in_aid)
                        if ((current_datetime - datetime.fromtimestamp(aid_data["start_time"])).days) < scan_period:
                            target_hosts.append(aid_data)
                else:
                    target_hosts.append(
                        {"aid": aid, "start_time": current_datetime.timestamp(), "scan_count": 0, "scan_errors": 0})

            if len(target_hosts) > 0 and entry["existing"]:
                process_existing_target_hosts(target_hosts, entry['type'])

            elif len(target_hosts) > 0 and not entry["existing"]:
                process_new_target_hosts(target_hosts, entry['type'], current_datetime, batches)

        batches.put(entry)


def prepare_processors(queue):
    for x in range(0, threads):
        print(f"Starting Queue Process: {str(x)}")
        reader_p = Process(target=queue_processor, args=(queue,))
        reader_p.start()
        all_reader_procs.append(reader_p)


def run(name):
    if name == "__main__":
        print(f"Running Scratch2 Process")
        queue = Queue()
        try:
            # prepare_processors(queue)
            build_processor(queue)
            queue_processor(queue)
            # for proc in all_reader_procs:
            #     proc.join()
        except Exception as ex:
            print(str(ex))

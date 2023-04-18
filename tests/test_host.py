import json
import os
import sys
import glob
import pandas as pd

# Import our sibling src folder into the path
sys.path.append(os.path.abspath('src'))

# Classes to test - manually imported from sibling folder
import dtCrowdstrike
from dtCrowdstrike.client import CrowdstrikeClient

print('glob')
system_infos = []
for name in glob.glob('/Users/matthewe/Downloads/untitled folder 4/adg/**/*.json', recursive = True):
    with open(name, "r") as in_json:
        system_infos.append(json.load(in_json)['system_info'])

data = {"ou": []}
processed_count = 0
found_keys = ['ou']
for detail in system_infos:
    for key in detail:
        if isinstance(detail[key], str) or isinstance(detail[key], int) or isinstance(detail[key], bool):
            if key not in found_keys:
                found_keys.append(key)

for detail in system_infos:
    processed_keys = []
    for key in found_keys:
        if key in detail and (isinstance(detail[key], str) or isinstance(detail[key], int) or isinstance(detail[key], bool)):
            if key not in data:
                data[key] = []
                if processed_count > 0:
                    for x in range(processed_count):
                        data[key].append(None)

            data[key].append(detail[key])
        elif key == 'ou' and key in detail:
            data[key].append("/".join(detail[key]))
        elif key == 'ou' and key not in detail:
            data[key].append(None)
        else:
            if key not in data:
                data[key] = []
            data[key].append(None)


    # for key in data:
    #     if key not in processed_keys:
    #         data[key].append(None)

df = pd.DataFrame(data)
df.to_excel('servers extended_detail_Jan2023.xlsx', sheet_name="Servers", index=False)
print('done')
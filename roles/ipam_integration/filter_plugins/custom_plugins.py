import requests
from pprint import pprint

token = "LUFRPT1TSTUzc05WRGhUTVpuV0tmOGc5VVRmdGZsU289bXR6YWZmc2FPS1JxeUVaQ0tPTlhaQWVycEU5Vi9OYTc5a1FtRXBkQkpJbWxveDlsc29vbGEzMVNsWElqV3NyWVZ3RUZCVTBqVUhmTW5YdUQ5NVFoYnc9PQ=="
VIRTUAL_SYSTEMS = ["vsys2", "vsys5", "vsys7", "vsys9", "vsys10", "vsys11", "vsys13"]
meta_data = [
    {
        "location": "phx3",
        "firewalls": [
            "https://phx3-fwe-a.internal.salesforce.com"
        ], 
        "networks": [
            "13.110.54.0/24"
        ]
    }
]


def isRequiredIP(ip, network):
    ip_vals = ip.split('.')
    network_vals = network.split('.')
    return ip_vals[0] == network_vals[0]

def populate(result, response, network):
    if 'entry' not in response['result']: 
        return 
    for item in response['result']['entry']:
        basic = {
            'name': item['@name'],
            'vsys': item['@vsys'], 
            'description': item['description'] if 'description' in item else ''
        }
        
        if 'destination' in item and 'member' in item['destination']:
            for ip in  item['destination']['member']:
                while len(ip) and (not (ip[0]>='0' and ip[0]<='9')):
                    ip = ip[1:]
                while len(ip) and (not (ip[-1]>='0' and ip[-1]<='9')):
                    ip=ip[:-1]
                idx=ip.find('/')
                if idx != -1:
                    ip=ip[0:idx]
                if isRequiredIP(ip, network):
                    data = basic
                    data['type'] = 'destination'
                    data['ip'] = ip
                    data['network'] = network
                    result.append(data)         

        if 'source-translation' in item and 'static-ip' in item['source-translation'] and 'translated-address' in item['source-translation']['static-ip']:
            ip = item['source-translation']['static-ip']['translated-address']
            while len(ip) and (not (ip[0]>='0' and ip[0]<='9')):
                ip = ip[1:]
            while len(ip) and (not (ip[-1]>='0' and ip[-1]<='9')):
                ip=ip[:-1]
            idx=ip.find('/')
            if idx != -1:
                ip=ip[0:idx]
            if isRequiredIP(ip, network):
                data = basic
                data['type'] = 'source-translation:static-ip'
                data['ip'] = ip
                data['network'] = network
                result.append(data)

        if 'source-translation' in item and 'dynamic-ip-and-port' in item['source-translation'] and 'translated-address' in item['source-translation']['dynamic-ip-and-port'] and 'member' in item['source-translation']['dynamic-ip-and-port']['translated-address']:
            for ip in item['source-translation']['dynamic-ip-and-port']['translated-address']['member']:
                while len(ip) and (not (ip[0]>='0' and ip[0]<='9')):
                    ip = ip[1:]
                while len(ip) and (not (ip[-1]>='0' and ip[-1]<='9')):
                    ip=ip[:-1]
                idx=ip.find('/')
                if idx != -1:
                    ip=ip[0:idx]
                if isRequiredIP(ip, network):
                    data = basic
                    data['type'] = 'source-translation:dynamic-ip-and-port'
                    data['ip'] = ip
                    data['network'] = network
                    result.append(data)

class FilterModule(object):
    def filters(self):
        return {
            'get_fw_ips': self.get_fw_ips,
        }

    def get_fw_ips(self, data):
        try:
            path = "/restapi/v10.1/Policies/NATRules"
            headers = {
                "Content-Type": "application/json",
                "X-PAN-KEY": token
            }

            result = []

            for item in meta_data:
                network = item['networks'][0]
                for URL in item["firewalls"]:
                    for vsys in VIRTUAL_SYSTEMS:
                        params = {
                            "location": "vsys", 
                            "vsys": vsys
                        }
                        response = requests.get(URL + path, headers=headers,
                                            params=params, verify=False)      
                        if response.status_code == 200:
                            response=response.json()      
                            populate(result, response, network)

            return result
        except Exception as e:
            pprint("Something went wrong: " + str(e))

      


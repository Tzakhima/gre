'''
This script is used to configure GRE tunnel between Fortigate and VyOS.
Using FortiOS API for Fortigate configuration and Netmiko for VyOS configuration.
Tzakhi Malka
Tzakhi@malnet.co.il
'''


import requests
import json
import urllib3
from netmiko import ConnectHandler
import getpass
from netaddr import *


#disable SSL warnings
urllib3.disable_warnings()

#Variable for BOLD text
bold = "\033[1m"
reset = "\033[0;0m"


def get_cookie(session):
    cookie = {}
    for k, v in session.cookies.items():
        cookie[k] = v
    return cookie

# Get user input for basic info

print ('\n[*]This Script Will Configure GRE Tunnel Between Fortigate And VyOS')
print ('[*]The Following Information Is Needed:')

print ('\nFortigate Parameters:')
print ('~'*50)
forti_wan_ip        = input('Please Enter Fortigate management IP adddress: ')
forti_wan_port      = input('Please Enter Fortigate HTTPS port: ')
forti_user          = input('Please Enter Fortigate Admin Username: ')
forti_pass          = getpass.getpass(prompt='Please Enter Fortigate Admin Password: ')
print('\nVyOS Parameters:')
print('~'*50)
vyos_wan_ip         = input('Please Enter VyOS WAN IP adddress: ')
vyos_user           = input('Please Enter VyOS Admin Username: ')
vyos_pass           = getpass.getpass(prompt='Please Enter VyOS Admin Password: ')



# Get authentication token (cookies) from Fortigate
auth_url = 'https://'+forti_wan_ip+':'+forti_wan_port+'/logincheck'
PARAMS = {'username':forti_user, 'secretkey':forti_pass}
session = requests.session()
auth_req = session.post(url = auth_url, params = PARAMS, verify=False)
cookies = get_cookie(auth_req) # Store all cookies as a dict
cookies_2 = auth_req.cookies   # Get all cookies as is
for cookie in cookies_2:       # Get the ccsfrtoken to send as header
    if cookie.name == "ccsrftoken":
        csrftoken = cookie.value[1:-1]  # token stored as a list
        header = {"X-CSRFTOKEN": csrftoken}


##### Fortigate Config #####

# Get Interfaces And IP#################################################################################################
# And Setting Parameters ###############################################################################################

api_url = 'https://'+forti_wan_ip+':'+forti_wan_port+'/api/v2/cmdb/system/interface'

interfaces = session.get(url = api_url,cookies=cookies, headers=header, verify=False)

resp = interfaces.content
resp = json.loads(resp)

items = resp['results']

name_dict = {}
i=0
for key in items:
    if  '0.0.0.0' not in key['ip']:
        name_dict.update({i : {'name':key['name'],'ip':key['ip']}})
        i += 1


print("\nPlease Choose Fortigate --WAN-- interface For Tunneling: ")
print("~"*35)

# WAN section
for k in name_dict:
    full_ip = name_dict[k]['ip']
    ip = full_ip.split()
    ip_add = ip[0]
    print( "["+str(k)+"]"+" "+name_dict[k]['name'])
    print("-"*20)
    print("\tIP Address: "+ip_add+"\n")
wan_choice = input("Choose One Of The Above (The Number Inside The '[]' ): ")

forti_wan_ip_full  = name_dict[int(wan_choice)]['ip']
forti_wan_ip_split = forti_wan_ip_full.split()
forti_wan_ip_tun   = forti_wan_ip_split[0]
forti_interface    = name_dict[int(wan_choice)]['name']

# LAN section
print("\nPlease Choose Fortigate ==LAN== interface For Tunneling: ")
print("~"*35)

for k in name_dict:
    if str(k) != str(wan_choice):
        full_ip = name_dict[k]['ip']
        ip = full_ip.split()
        ip_add = ip[0]
        print( "["+str(k)+"]"+" "+name_dict[k]['name'])
        print("-"*20)
        print("\tIP Address: "+ip_add+"\n")
lan_choice = input("Choose One Of The Above (The Number Inside The '[]' ): ")

forti_lan_ip_full   = name_dict[int(lan_choice)]['ip']
forti_lan_split     = forti_lan_ip_full.split()
forti_lan_net       = forti_lan_split[0]
forti_lan_mask      = str(sum([bin(int(x)).count('1') for x in forti_lan_split[1].split('.')]))
ip_cidr             = IPNetwork(forti_lan_net+'/'+forti_lan_mask)
forti_ip_and_cidr   = str(ip_cidr.cidr)
forti_lan_interface = name_dict[int(lan_choice)]['name']

########################################################################################################################




# API urls

api_url = 'https://'+forti_wan_ip+':'+forti_wan_port+'/api/v2/cmdb'


# Creating System GRE-TUNEEL
payload = {"name":"GRE-TUN",
      "interface":forti_interface,
      "remote-gw":vyos_wan_ip,
      "local-gw":forti_wan_ip_tun,
      "dscp-copying":"disable",
      "keepalive-interval":0,
      "keepalive-failtimes":10}

# For Updating Configuration On Existing Fortigate Config
payload_put = {
      "interface":forti_interface,
      "remote-gw":vyos_wan_ip,
      "local-gw":forti_wan_ip_tun,
      }


print('Adding System-GRE configuration...\n')
try:
    add_system_gre = session.post(url = api_url+'/system/gre-tunnel/',cookies=cookies, headers=header, json={'json': payload})
    add_system_gre_put = session.put(url =  api_url + '/system/gre-tunnel/GRE-TUN/', cookies=cookies, headers=header, json={'json': payload_put})
    print (add_system_gre_put.json())
except:
    print('Something Went Wrong With SYSTEM-GRE Creation')
    exit()


# Creating Tunnel Interface
payload = {
      "ip":"172.31.255.2 255.255.255.255",
      "allowaccess":"ping",
      "mtu-override":"enable",
      "mtu":1472,
      "tcp-mss":1300,
      "interface":"wan",
      "remote-ip":"172.31.255.1 255.255.255.255"}


print('\nAdding GRE Interface configuration...\n')
try:
    add_gre_interface = session.put(url = api_url+'/system/interface/GRE-TUN/',cookies=cookies, headers=header, json={'json': payload})
    print (add_gre_interface.json())
except:
    print('Something Went Wrong With Tunnel Interface Creation')
    exit()


# Creating Route Policy
payload = {"seq-num":1,
      "src":[
        {
          "subnet":forti_ip_and_cidr,
        }
      ],
      "srcaddr":[
      ],
      "src-negate":"disable",
      "dst":[
      ],
      "dstaddr":[
      ],
      "dst-negate":"disable",
      "action":"permit",
      "protocol":0,
      "start-port":1,
      "end-port":65535,
      "start-source-port":1,
      "end-source-port":65535,
      "gateway":"172.31.255.1",
      "output-device":"",
      "tos":"0x00",
      "tos-mask":"0x00",
      "status":"enable",
      "comments":""
      }


print('\nAdding Route Policy configuration...\n')
try:
    add_route_policy = session.post(url = api_url+'/router/policy/',cookies=cookies, headers=header, json={'json': payload})
    add_route_policy = session.put(url=api_url + '/router/policy/1/', cookies=cookies, headers=header,json={'json': payload})
    print (add_route_policy.json())
except:
    print('Something Went Wrong With Route Policy Creation')
    exit()




# Creating Policy to Allow Internet Access
payload = {
            "action": "accept",
            "dstaddr": [{"name": "all"}],
            "dstintf": [{"name": "GRE-TUN"}],
            "name": "GRE-Created By API",
            "nat": "disable",
            "policyid": 100,
            "schedule": "always",
            "service": [{"name": "ALL"}],
            "srcaddr": [{"name": "all"}],
            "srcintf": [{"name": forti_lan_interface}],
            "status": "enable"
          }


print('\nAdding Policy configuration...\n')
try:
    add_policy = session.post(url = api_url+'/firewall/policy',cookies=cookies, headers=header, json={'json': payload})
    add_system_gre = session.put(url=api_url + '/firewall/policy/100/', cookies=cookies, headers=header,json={'json': payload})
    print (add_policy.json())
except:
    print('Something Went Wrong With Policy Creatiom')
    exit()



session.close()



#### VyOS Config ####

print('\nConfiguring VyOS Device - It can take few minutes')
print('~'*50)

vyos = {
       'device_type': 'vyos',
       'ip':   vyos_wan_ip,
       'username': vyos_user,
       'password': vyos_pass,
       }

config_commands = [
'set interfaces tunnel tun0 address 172.31.255.1/32',
'set interfaces tunnel tun0 encapsulation gre',
'set interfaces tunnel tun0 local-ip '+vyos_wan_ip,
'set interfaces tunnel tun0 mtu 1360',
'set interfaces tunnel tun0 multicast disable',
'set interfaces tunnel tun0 remote-ip '+forti_wan_ip,
'set nat source rule 10 outbound-interface eth0',
'set nat source rule 10 source address '+forti_ip_and_cidr,
'set nat source rule 10 translation address masquerade',
'set policy route MSS-CLAMP rule 10 protocol tcp',
'set policy route MSS-CLAMP rule 10 set tcp-mss 1300',
'set policy route MSS-CLAMP rule 10 tcp flags SYN',
'set protocols static interface-route '+forti_ip_and_cidr+' next-hop-interface tun0',
'set protocols static interface-route 172.31.255.2/32 next-hop-interface tun0',
'set interfaces ethernet eth0 policy route MSS-CLAMP',
'commit',
'save'
]
try:
    net_connect = ConnectHandler(**vyos)
except:
    print('Error While Connecting To VyOS.')
    print('Fortigate Configured but VyOS not... ')
    print('Quitting...')
    exit()

output = net_connect.send_config_set(config_commands)
print(output)


### Testing ###

print('\nTesting Tunnel - executing PING from VyOS to Fortigate:')
print('~'*50)
ping = net_connect.send_command('run ping 172.31.255.2 count 5')
print(ping)





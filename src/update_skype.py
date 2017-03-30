'''
Created on Mar 1, 2017

@author: Wyko
'''

import argparse, textwrap, re, cli
import urllib.request as url

from xml.etree import ElementTree as ET
from datetime import datetime
from netmiko import ConnectHandler
from time import sleep


def connect_firewall(user= None, password= None):
    '''
    Establishes a connection to a firewall and enters enable mode.
    
    Returns:
        connection: A Netmiko connection object
    ''' 
    
    connection= cli.start_cli_session(
                          handler= ConnectHandler, 
                          netmiko_platform= 'cisco_asa_ssh', 
                          ip= '10.20.254.26',
                          cred={'user': user,
                                'password': password,
                                'type': None} ,
                          port= 22)['connection']
    
    if not cli.enable(connection): return False
    
    return connection    
    


def parse_cli():
    parser = argparse.ArgumentParser(
        prog= 'update_365',
        formatter_class= argparse.RawTextHelpFormatter,
        description=textwrap.dedent(
            '''\
            Automatically downloads the XML file from 
            https://support.content.office.net/en-us/static/O365IPAddresses.xml 
            and generates a Cisco ASA firewall network object config for it
            '''))
    
    parser.add_argument(
        '-u',
        action="store",
        dest= 'user',
        help= 'Username',
        )
    
    parser.add_argument(
        '-p',
        action="store",
        dest= 'password',
        help= 'Password',
        )
    
    parser.add_argument(
        '-kV',
        action="store_true",
        dest= 'kv',
        help= 'Keep all Verisign fqdn entries (normally deleted)',
        default = False
        )
    
    parser.add_argument(
        '-kW',
        action="store_true",
        dest= 'kw',
        help= 'Keep all wildcard entries (normally deleted)',
        default = False
        )
    
    parser.add_argument(
        '-kS',
        action="store_true",
        dest= 'ks',
        help= 'Keep all subdomain entries (normally trimmed to parent domain)',
        default = False
        )
    
    return parser.parse_args()


def get_o365_ips(product,
        msURL= 'https://support.content.office.net/en-us/static/O365IPAddresses.xml'
        ):
    '''
    Connects to Microsoft and downloads their public IP list.
    
    Keyword Args: 
        msURL (str): The full URL of the Microsoft IP list. Defaults to
            `https://support.content.office.net/en-us/static/O365IPAddresses.xml`
            
    Returns:
        dict: A dict containing:
        
            - **product** (*str*): The name of the product
            - **url_list** (*list of str*): Contains the FQDN's
            - **ip_list** (*list of dicts*): Contains a list of IP addresses
                in the form of:
                
                - ip
                - cidr
                - netmask
    '''
    
    # Download the XML file from Microsoft containing the
    # IP addresses required for Office 365
    response= url.urlopen(msURL)
    page= response.read()
    
    # Import the XML into a reader
    root = ET.fromstring(page)
    
    # Parse the IP and URL info
    p= root.find("./product[@name='{}']".format(product))
    ipv4= p.find("./addresslist[@type='IPv4']")
    urls= p.find("./addresslist[@type='URL']")
    
    # Parse IP's from XML
    for element in ipv4.iter('address'):
        ip= element.text.split("/")
        mask= cidr_to_netmask(ip[1])
        ip_list.append({
                        'ip': ip[0],
                        'cidr': ip[1],
                        'mask': mask,
                        'text': '{:15} {}'.format(ip[0], mask)
                      })
        
    # Parse FQDN's from XML
    for element in urls.iter('address'):
        text= element.text
        # Remove Wildcards
        if not args.kw and ('*' in text): continue
        # Remove Verisign
        if not args.kv and ('verisign' in text): continue
        # Remove subdomains and leave only parent domains
        if not args.ks: text= text.split('/')[0]
        
        if not text in url_list: url_list.append(text)
    
    return {
        'product': product,
        'url_list': url_list,
        'ip_list': ip_list
        }
    
    

def main():
    args= parse_cli()
    
    connection= connect_firewall(user= getattr(args, 'user', None),
                                 password= getattr(args, 'password', None))
     
    connection.send_command('changeto context CORPINET')
    
    top_group= connection.send_command_expect(
        'sh run object-group id Net-grp-Skype-for-Business-or-Lync-IPv4-Addresses')

    

    # Generate the configuration    
    object_group= textwrap.dedent('''\
            !
            object-group network Net-grp-Skype-for-Business-or-Lync-IPv4-Addresses
            ''')
    
    object_network= ''
    
    url_list= []
    ip_list= []
    rule_log= ''
    

    
    for x in ip_list:
        
        # Check to see if the IP string is in the object group already
        if x['ip'] in top_group:
            x['text']+= ' - Already in firewall'
            #===================================================================
            # print('Already in rules: {}'.format(x['ip']))
            #===================================================================
            rule_log+= 'Already in rules: {}'.format(x['ip'])
            continue
        
        # Otherwise, prepare the object to add to the firewall
        if x['cidr']== '32':
            name= 'HOST-EXT-{}'.format(x['ip'])
            object_group+= '    network-object {}\n'.format(name)
            object_network+= textwrap.dedent('''\
                object network {1}
                    description IP address for Skype for Business
                    host {0}
                !
                '''.format(x['ip'], name))
        
        else:
            name= 'Net-EXT-IP-{}-SLASH-{}'.format(x['ip'], x['cidr'])
            object_group+= '    network-object {}\n'.format(name)
            
            object_network+= textwrap.dedent('''\
                object network {2}
                    description IP network for Skype for Business
                    subnet {0} {1}
                !
                '''.format(x['ip'], x['mask'], name))
            
        #=======================================================================
        # print('Added new rule: {}'.format(name))
        #=======================================================================
        rule_log+= 'Added new rule: {}'.format(name)
        
    # Prepare object groups for all the FQDN's
    object_network+= '!\n! FQDNs Here\n!\n'    
    for fqdn in url_list:
        name= 'fqdn-{}'.format(fqdn)
        object_group+= '    network-object {}\n'.format(name)
        
        object_network+= textwrap.dedent('''\
            object network {0}
                description FQDN address for Skype for Business
                fqdn {1}
            !
            '''.format(name, fqdn))
    
    with open('skype_config.cfg', 'w') as outfile:
        outfile.write('! Generated ' + datetime.now().strftime('%Y-%m-%d %H:%M:%S'+'\n'))
        outfile.write(object_network)
        outfile.write(object_group)
    
    with open('addresses.txt', 'w') as outfile:
        outfile.write('Generated ' + datetime.now().strftime('%Y-%m-%d %H:%M:%S'+'\n'))
        outfile.write('\n####### FQDN Addresses #######\n')
        for x in url_list:
            outfile.write(x + '\n')
        outfile.write('\n####### IP Addresses #######\n')
        for x in ip_list:
            outfile.write(x['text'] + '\n')
    
    with open('log.txt', 'w') as outfile:
        outfile.write(rule_log)
            
    print('Config written to skype_config.cfg')
    
if __name__ == '__main__':
    main()
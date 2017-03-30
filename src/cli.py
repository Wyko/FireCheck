'''
Created on Feb 28, 2017

@author: Wyko
'''

from util import port_is_open, getCreds
from netmiko import NetMikoAuthenticationException
from netmiko import NetMikoTimeoutException
from netmiko import ConnectHandler
from time import sleep
import util, gvars

def start_cli_session(handler= None,
                      netmiko_platform= None,
                      ip= None, 
                      cred= None, 
                      port= None):
    """
    Starts a CLI session with a remote device. Will attempt to use
    SSH first, and if it fails it will try a terminal session.
    
    Optional Args:
        cred (Dict): If supplied. this method will only use the specified credential
        port (Integer): If supplied, this method will connect only on this port 
        ip (String): The IP address to connect to
        netmiko_platform (Object): The platform of the device 
        handler (Object): A Netmiko-type ConnectionHandler to use. Currently using
            one of Netmiko.ConnectHandler, Netmiko.ssh_autodetect.SSHDetect. 
            Uses Netmiko.ConnectHandler by default.
    
    Returns: 
        Dict: 
            'connection': Netmiko ConnectHandler object opened to the enable prompt 
            'TCP_22': True if port 22 is open
            'TCP_23': True if port 23 is open
            'cred': The first successful credential dict 
            
    Raises:
        ValueError: If connection could not be established
        AssertionError: If error checking failed
    """
    proc= 'cli.start_cli_session'
    
    print('Connecting to %s device %s' % (netmiko_platform, ip))
    
    assert isinstance(ip, str), proc+ ': Ip [{}] is not a string.'.format(type(ip)) 
    
    result= {
            'TCP_22': port_is_open(22, ip),
            'TCP_23': port_is_open(23, ip),
            'connection': None, 
            'cred': None,
            }
    
    _credList= []
    if cred is not None: 
        _credList.append(cred)
    else:
        # Get credentials if none were acquired yet
        if len(gvars.CRED_LIST) == 0: gvars.CRED_LIST= getCreds()
        _credList= gvars.CRED_LIST
    
    # Error checking        
    assert len(_credList) > 0, 'No credentials available'
    if port: assert port is 22 or port is 23, 'Invalid port number [{}]. Should be 22 or 23.'.format(str(port))
    if cred: assert isinstance(cred, dict), 'Cred is type [{}]. Should be dict.'.format(type(cred))
    
    # Check to see if SSH (port 22) is open
    if not result['TCP_22']:
        print('Port 22 is closed on %s' % ip, ip)
    elif port is None or port is 22: 
        # Try logging in with each credential we have
        for cred in _credList:
            try:
                # Establish a connection to the device
                result['connection'] = handler(
                    device_type=netmiko_platform,
                    ip=  ip,
                    username= cred['user'],
                    password= cred['password'],
                    secret= cred['password'],
                )
                
                result['cred']= cred
#                 print('Successful ssh auth to %s using %s, %s' % (ip, cred['user'], cred['password'][:2]))
                
                return result
    
            except NetMikoAuthenticationException:
                print ('SSH auth error to %s using %s, %s' % (ip, cred['user'], cred['password'][:2]))
                continue
            except NetMikoTimeoutException:
                print('SSH to %s timed out.' % ip)
                # If the device is unavailable, don't try any other credentials
                break
    
    # Check to see if port 23 (telnet) is open
    if not result['TCP_23']:
        print('Port 23 is closed on %s' % ip, ip)
    elif port is None or port is 23:
        for cred in _credList:
            try:
                # Establish a connection to the device
                result['connection'] = handler(
                    device_type=netmiko_platform + '_telnet',
                    ip=  ip,
                    username= cred['user'],
                    password= cred['password'],
                    secret= cred['password'],
                )
                
                result['cred']= cred
#                 print('Successful telnet auth to %s using %s, %s' % (ip, cred['user'], cred['password'][:2]))
                
                return result
            
            except NetMikoAuthenticationException:
                print('Telnet auth error to %s using %s, %s' % 
                    (ip, cred['user'], cred['password'][:2]))
                continue
            except:
                print('Telnet to %s timed out.' % ip)
                # If the device is unavailable, don't try any other credentials
                break
    
    raise IOError('No CLI connection could be established')


def enable(connection, attempts= 3):
    '''Enter enable mode.
    
    Returns:
        bool: True if enable mode successful.
    '''
    
    for i in range(attempts):
        
        # Attempt to enter enable mode
        try: connection.enable()
        except Exception as e: 
            print('Enable failed on attempt %s. Error: %s' % (str(i+1), e))
            
            # At the final try, return the failed device.
            if i == attempts-1: 
                raise
            
            # Otherwise rest for one second longer each time and then try again
            sleep(i+2)
            continue
        else: 
#             print('Enable successful on attempt %s' % (str(i+1)))
            return True
        
def connect_firewall(host, 
                     user= None, 
                     password= None,
                     context= None,
                     ):
    '''
    Establishes a connection to a firewall and enters enable mode.
    
    Returns:
        connection: A Netmiko connection object
    ''' 
    
    connection= start_cli_session(
                      handler= ConnectHandler, 
                      netmiko_platform= 'cisco_asa_ssh', 
                      ip= host,
                      cred={'user': user,
                            'password': password,
                            'type': None} ,
                      port= 22)['connection']
        
    if not enable(connection): return False
    
    # Switch contexts   
    if context is not None: 
        print('Changing to context {}'.format(context))
        connection.send_command('changeto context {}'.format(context))
    
    return connection  






if __name__ == '__main__':
    main()
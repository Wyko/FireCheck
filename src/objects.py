'''
Created on Mar 24, 2017

@author: Wyko
'''

import argparse, textwrap, re, cli, util

from datetime import datetime
from netmiko import ConnectHandler
from time import sleep
import prettytable


def cidr_to_netmask(cidr):
    '''Changes CIDR notation to subnet masks. 
    I honestly have no idea how this works. I
    just added some error checking.'''
    
    # Strip any non digit characters
    if type(cidr) == str: 
        cidr= int(re.sub(r'\D', '', str(cidr)))
    else: cidr= int(cidr)
    
    if not (0 <= cidr <= 32):
        raise ValueError('Input CIDR not recognized as a valid netmask')
     
    return '.'.join([str((0xffffffff << (32 - cidr) >> i) & 0xff)
                    for i in [24, 16, 8, 0]])

 
    
def parse_cli():
    parser = argparse.ArgumentParser(
        prog= 'FireCheck',
        formatter_class= argparse.RawTextHelpFormatter,
        description=textwrap.dedent(
            '''\
            Various tools for interacting with a Cisco ASA firewall
            '''))

    parser.add_argument(
        '-m',
        action="store_true",
        dest= 'members',
        help= 'Print the members of each group',
        )
    
    parser.add_argument(
        '-h',
        action="store",
        dest= 'host',
        help= 'Network address of the firewall',
        )
    
    parser.add_argument(
        '-c',
        action="store",
        dest= 'context',
        help= 'Change to the specified context',
        default= None,
        )

    #===========================================================================
    # parser.add_argument(
    #     '-p',
    #     action="store_true",
    #     dest= 'print',
    #     help= 'Print',
    #     )
    #===========================================================================
    
    parser.add_argument(
        '-w',
        action="store_true",
        dest= 'wait',
        help= 'Wait after printing each entry (if -p)',
        )
     
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
     
    return parser.parse_args()


class objectGroup():
    def __init__(self, **kwargs):
        self.name= kwargs.get('name')
        self.description= kwargs.get('description')
        self.members= kwargs.get('members', [])
        
    def __str__(self):
        pt= prettytable.PrettyTable(['Name', self.name])
        pt.align= 'l'
        
        for item in dir(self):
            if item == 'members':
                pt.add_row(['Members', ''])
                for m in self.members:
                    pt.add_row(['', m['type'] + ': ' + m['target']])
            
            elif not item.startswith("_") and 'name' not in item: 
                pt.add_row([item.title(), getattr(self, item)])
                
        return str(pt)
        
    @property
    def weight(self):
        total= 0
        if len(self.members) == 0: return 0
        
        for x in self.members:
            if x['type']== 'object': 
                total+= self._object_weight(x['target'])
            
            elif x['type']== 'group-object': 
                total+= self._object_group_weight(x['target'])
            
            elif x['type']== 'network': 
                total+= 1
            
            
            else:
                raise TypeError('Unknown object type: [{}]'.format(x['type']))
        
        return total
    
    def _object_weight(self, name):
        '''Searches the global list of network objects for a match with the 
        same name as the `name` argument, then returns it's weight.'''
        global objects
        
        # Search the global objects list for a match
        for o in objects:
            if name== o.name:
                return o.weight
            
        # Raise an error if the object was not found
        raise ValueError('Object [{}] referenced in object group [{}] but '
            ' not found in objects'.format(o.name, self.name))
        
    def _object_group_weight(self, name):
        global object_groups
        
        # Search the global objects list for a match
        for o in object_groups:
            if name== o.name:
                return o.weight
            
        # Raise an error if the object was not found
        raise ValueError('Object-group [{}] referenced in object group [{}] but '
            ' not found in objects'.format(o.name, self.name))
        

class networkObject():
    def __init__(self, **kwargs):
        self.name= kwargs.get('name')
        self.description= kwargs.get('description')
        self.type= kwargs.get('type')
        self.target= kwargs.get('target')
        
    def __str__(self):
        pt= prettytable.PrettyTable(['Name', self.name])
        pt.align= 'l'
        
        for item in dir(self):
            if item == 'members':
                pt.add_row(['Members', ''])
                for m in self.members:
                    pt.add_row(['', m['type'] + ': ' + m['target']])
            
            elif not item.startswith("_") and 'name' not in item: 
                pt.add_row([item.title(), getattr(self, item)])
                
        return str(pt)

    @property
    def weight(self):
        # Weight fqdn's heavier
        if self.type== 'fqdn': return 3
        else: return 1
        

def split_objects(strobjects):
    '''Takes the output of `show run object(-group) network`
    from a firewall and splits it into a list of objects
    '''
    
    results= re.findall(r'^(\w.*?$[\s\S]*?)(?=^\w)', strobjects, re.M)
    return results
    

def process_objects(strobjects):
    '''Takes the output of `show run object network`
    from a firewall and converts it into a list of
    networkObject objects
    '''
    
    split_list= split_objects(strobjects)
    
    objects= []
    for x in split_list:
        n= networkObject()
        name= re.match(r'^object network (.*?)$', x, re.M)
        if name is None or name[1] is None: 
            raise ValueError('Problem parsing name in [\n{}\n]'.format(x))
        else: n.name= name[1] 
        
        # Get the description. Does not fail if not found.
        desc= re.search(r'^ description (.*?)$', x, re.M|re.I)
        if desc is not None and desc[1] is not None:
            n.description = desc[1]
        
        # Get the type, with some error checking 
        result= re.search(r'^ (host|subnet|range|fqdn) (.*)?$', x, re.M|re.I)
        if (result is None or
            result.group(1) is None or
            result.group(2) is None): 
            n.type= None
            n.target= None
        else:
            n.type= result.group(1)
            
            if n.type == 'subnet':
                t= result.group(2).split(' ')
                n.target = t[0]
                n.cidr= util.netmask_to_cidr(t[1])
            
            if n.type== 'host':
                n.target= result.group(2)
                n.cidr= 32
                
            else:
                n.target= result.group(2)
            
        objects.append(n)    
        
    return objects    


def process_object_groups(strobjects):
    '''Takes the output of `show run object-group network`
    from a firewall and converts it into a list of
    objectGroup objects
    '''
    
    split_list= split_objects(strobjects) 
    
    objects= []
    for x in split_list:
        n= objectGroup()

        #Get members
        for line in x.split('\n'):
            
            # Skip blank lines
            if re.match(r'^\s*?$', line): continue
            
            name= re.match(r'^object-group network (.*?)$', line, re.M)
            if not (name is None or name[1] is None): 
                n.name= name[1]
                continue 
            
            # Get the description. Does not fail if not found.
            desc= re.search(r'^ description (.*?)$', line, re.M|re.I)
            if desc is not None and desc[1] is not None:
                n.description = desc[1]
                continue
            
            # Check if it's a network-object 
            result= re.match(r'^ network-object (.*?) (.*?)$', line, re.M|re.I)
            if not (result is None or
                result.group(1) is None or
                result.group(2) is None): 
                
                # If the network_object is a address/mask combo
                if util.is_ip(result[1]) and util.is_ip(result[2]):
                    n.members.append(
                    {'type': 'network',
                     'target': result[1] + ' / ' + result[2]
                    })
                    
                else:
                    n.members.append(
                        {'type': result[1],
                         'target': result[2]
                        })
                continue
            
            # Check if it's an object-group
            result= re.match(r'^ group-object (.*?)$', line, re.M|re.I)
            if not (result is None or result[1] is None):
                n.members.append(
                    {'type': 'group-object',
                     'target': result[1]
                    })
                continue

            raise ValueError('None result found from line [{}]'.format(line))
                    
        objects.append(n)    
    return objects    
    
       
def printObjects(objects, wait, members):
    with open('firewall_object_complexity_report.txt', 'w') as outfile:
        for x in sorted(objects, key=lambda y: y.weight, reverse=True):
            pt= prettytable.PrettyTable(['Name', x.name])
            pt.align= 'l'
            
            for item in dir(x):
                if item == 'members':
                    if members:
                        pt.add_row(['Members', ''])
                        for m in x.members:
                            pt.add_row(['', m['type'] + ': ' + m['target']])
                
                elif not item.startswith("_") and 'name' not in item: 
                    pt.add_row([item.title(), getattr(x, item)])
                
            outfile.write(str(pt) + '\n')
            print(pt)
            if wait: input('...')
        

def getObjects_fromFirewall(host,
                            username= None,
                            password= None,
                            context= None): 
    '''
    Connects to a remote firewall and collects the objects from it, then
    saves those objects into python class objects'''
      
    connection= cli.connect_firewall(user= username,
                                 password= password,
                                 host= host,
                                 context= context,
                                 )
    
    print('Getting objects')
    objects= connection.send_command_expect(
        'show run object network', delay_factor= 10)
    
    # Save the objects to file
    with open('objects.txt', 'w') as outfile: outfile.write(objects)
      
    print('Getting object-groups')
    object_groups= connection.send_command_expect(
        'show run object-group network', delay_factor= 10)
    
    # Save the object groups to file
    with open('objectgroups.txt', 'w') as outfile: outfile.write(object_groups)
    
    objects= process_objects(objects)
    object_groups= process_object_groups(object_groups)
    
    connection.close()
    
    return {'objects': objects, 'groups': object_groups}
    

def getObjects_fromFile(): 
    '''Imports previously saved objects from files'''
    
    global objects, object_groups
    
    with open('objects.txt', 'r') as infile: 
        objects= infile.read()
    
    with open('objectgroups.txt', 'r') as infile: 
        object_groups= infile.read()
        
    objects= process_objects(objects)
    object_groups= process_object_groups(object_groups)
    
    return {'objects': objects, 'groups': object_groups}
    
    
def main():
    args= parse_cli()
    


if __name__ == '__main__':
    main()
    
    
    
    
    
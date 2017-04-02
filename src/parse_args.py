'''
Created on Mar 31, 2017

@author: Wyko
'''

import argparse, textwrap


def make_parser() -> argparse.ArgumentParser:
    '''
    Uses argparse to create a CLI parser fully populated with the arguments. 
    Creation of the parser and its execution were separated in order 
    to ensure compatibility with Sphinx's CLI auto-documentation. 
    
    Returns:
        argparse.ArgumentParser: A parser object ready for use in parsing a 
        CLI command
    '''
    
    parser = argparse.ArgumentParser(
        prog='FireCheck',
        formatter_class=argparse.RawTextHelpFormatter,
        )
    
    creds = parser.add_argument_group('Credentials')
    target = parser.add_argument_group('Target Specification')
    
    creds.add_argument(
        '-u',
        action="store",
        dest= 'username',
        help= 'Username',
        )
    
    creds.add_argument(
        '-p',
        action="store",
        dest= 'password',
        help= 'Password',
        )
    
    target.add_argument(
        '-t',
        action="store",
        dest= 'host',
        help= 'Network address of the firewall',
        )
    
    target.add_argument(
        '-c',
        action="store",
        dest= 'context',
        help= 'Change to the specified context',
        default= None,
        )
    
    
    return parser


def parse_args():
    '''
    Creates an argparse CLI parser and parses the CLI options.
    
    Returns:
        argparse.Namespace: A simple class used to hold the 
        attributes parsed from the command line.
    '''
    
    parser= make_parser()
    args = parser.parse_args()
     
    return args


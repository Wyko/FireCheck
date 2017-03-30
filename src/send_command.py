import argparse, textwrap, cli
import sys


def parse_cli():
    parser = argparse.ArgumentParser(
        prog= 'FireCheck - Send',
        formatter_class= argparse.RawTextHelpFormatter,
        description=textwrap.dedent(
            '''\
            Sends a command to a firewall
            '''))

    parser.add_argument(
        '-t',
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
        action="store",
        dest= 'command',
        help= 'The command to send',
        )
    
    return parser.parse_args()



def main():
    args= parse_cli()
    
    try:
        connection= cli.connect_firewall(user= getattr(args, 'user', None),
             password= getattr(args, 'password', None),
             host= args.host,
             context= args.context,
             )
    except IOError:
        print('No connection could be established.')
        sys.exit()

    input('Ready to send: ' + args.command)
    result= connection.send_command_expect(
        args.command, delay_factor= 10)
    
    with open(args.command[:5] + '.txt', 'w') as outfile:
        outfile.write(result) 
    
    print(result)

if __name__ == '__main__':
    main()
    
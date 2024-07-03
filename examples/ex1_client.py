''' Minimum example for setting up a command line client using Pyfrost.
'''

from pyfrost.pf_client import *
from colorama import Fore, Style
import os
import argparse

if os.name != 'nt':
	import readline
	
CLI_AUTOSYNC = True

parser = argparse.ArgumentParser()
parser.add_argument('-l', '--local', help="Use localhost instead of intranet address.", action='store_true')
args = parser.parse_args()

# Create socket - this is not protected by a mutex and should only ever be used by the main thread
if args.local:
	ip_address = "localhost"
else:
	ip_address = "192.168.1.116"


def custom_func(ca:ClientAgent, opt:ClientOptions, words:list) -> bool:
	
	# Get command string
	cmd = words[0].str
	
	# Process command
	if cmd.upper() == "EX1":
		print("Hey! You triggered the custom function.")
		return True
	
	return False

if __name__ == '__main__':
	
	log = LogPile()
	
	# Create client agent
	ca = ClientAgent(log)
	ca.set_addr(ip_address, 5555)
	ca.connect_socket()
	
	# Create client options
	copt = ClientOptions()
	
	# Run CLI
	commandline_main(ca, copt, custom_func)


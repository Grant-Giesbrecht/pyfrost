''' Minimum example for setting up a server using Pyfrost.
'''

from pyfrost.pf_server import *
import time
from pylogfile import *
import logging
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-l', '--local', help="Use localhost instead of intranet address.", action='store_true')
args = parser.parse_args()

# Create socket - this is not protected by a mutex and should only ever be used by the main thread
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(SOCKET_TIMEOUT)
if args.local:
	sock.bind(("localhost", 5555))
else:
	sock.bind(("192.168.1.116", 5555))
sock.listen()

def custom_func(sa:ServerAgent, gc:GenCommand) -> bool:
	return False

if __name__ == "__main__":
	
	server_main(sock, custom_func)
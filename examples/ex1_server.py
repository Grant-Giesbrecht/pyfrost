''' Minimum example for setting up a server using Pyfrost.
'''

from pyfrost.pf_server import *
from pylogfile.base import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-l', '--local', help="Use localhost instead of intranet address.", action='store_true')
parser.add_argument('-d', '--detail', help="Show detailed log messages.", action='store_true')
parser.add_argument('--loglevel', help="Set the logging display level.", choices=['LOWDEBUG', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], type=str.upper, default="WARNING")
args = parser.parse_args()

# Create socket - this is not protected by a mutex and should only ever be used by the main thread
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(SOCKET_TIMEOUT)
if args.local:
	sock.bind(("localhost", 5555))
else:
	sock.bind(("192.168.1.116", 5555))
sock.listen()

def custom_func(sa:ServerAgent, gc:GenCommand) -> GenData:
	''' This will process GenCommand objects received by the server from clients that DO expect a network response in the form of a GenData object.
	'''
	
	print(f"\n\nQUERY FUNC\n\n")
	
	if gc.command == "NUM-CLIENTS":
		
		data = GenData({"number":14}) #TODO: Make this a real number
		return data
	
	else:
		
		print(f"Didn't recognize command. {gc.command}")
		print(gc)

def custom_send_func(sa:ServerAgent, gc:GenCommand) -> bool:
	'''
	This will process GenCOmmand obkjects received by the server from the clients that expent NO NETWORK RESPONSE from the server.'''
	
	print(f"\n\nSEND FUNC\n\n")
	
	if gc.command == "NUM-CLIENTS":
		
		data = GenData({"number":14}) #TODO: Make this a real number
		return data

if __name__ == "__main__":
	
	server_main(sock, query_func=custom_func, send_func=custom_send_func, use_gui=True, loglevel=args.loglevel, detail=args.detail)
import socket
import rsa
import tabulate
import threading
import hashlib
import sqlite3
import msgpack
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from pylogfile.base import *
from pyfrost.base import *
from typing import Callable
from getpass import getpass

# from stardust.io import dict_summary
from stardust.cli import SettingsCLI

# Initialize database access
db_mutex = threading.Lock() # Create a mutex for the database

ENC_FALSE = 100
ENC_AUTO = 101
ENC_TRUE = 102

DEFAULT_CLIENTAGENT_SETTINGS = {
	"autosync-post-command": {"value": True, "desc": "Enable automatic syncs after sending commands to server."},
}

# @dataclass
# class ClientOptions:
# 	''' Stores options for the client agent that will get passed to both
# 	commandline_main() and commandline_extended().'''
# 	
# 	cli_autosync = True

class ClientAgent:
	""" This class handles networking for the client. It communicates with the
	server and handles encryption and login.
	"""
	
	# Client State Objects
	CS_HAND = 1 # Need to perform handshake - not encrypted. Perhaps not connected to server.
	CS_LOGIN = 2 # At login/signup phase - not authorized
	CS_MAIN = 3 # Connected to server, can perform primary operations
	
	def __init__(self, log:LogPile, address:str=None, port:int=None, connection_state=None, stowaway=None, help_source:str=None, topic_source:str=None, settings_source:str=None):
		
		# Save log object
		self.log = log
		
		if settings_source is None:
			self.settings_manager = SettingsCLI(None, False, DEFAULT_CLIENTAGENT_SETTINGS)
		else:
			self.settings_manager = SettingsCLI(settings_source, False)
		
		self.help_source = help_source
		self.help_data = {}
		self.load_help_data()
		
		self.topic_source = topic_source
		self.topic_data = {}
		self.load_topic_data()
		
		self.sock = None
		self.ipaddr = address
		self.port = port
		self.addr = (self.ipaddr, self.port)
		
		# Only firm requirement is that this object is a Packable. However, in
		# the pyfrost network model, this object is intended to house a state
		# machine that tracks the state of the connection to the server.
		self.connection_state = None
		
		# This is the lobby object. Fundamentally, the lobby object is saved on the server in
		# global memory. This is a local duplicate that is updated via `sync()` calls.
		self.lobby = None
		
		# The stowaway is an additional object you can add to the ClientAgent outside
		# of the typical pyfrost connection model. This was originally used to
		# house the self.connection_state object before this became a formailzed
		# variable.
		self.stowaway = None
		
		self.user = None # If logged in, this is the connected user
		
		# Generate keys
		self.public_key, self.private_key = rsa.newkeys(1024)

		# Server's public key
		self.server_key = None
		
		# AES variables
		self.aes_key = None
		self.aes_iv = None
		
		self.error_code = None # Code from last error. This will also be replaced by reply() replies that begin with 'ERROR:'
		self.reply = "" # string from last query
		
		#------------------------------------------------------------------#
		# These are parameters synced from the server
		
		self.notes = []
		
		# self.sharedata = ThreadSafeDict()
		
		self.state = ClientAgent.CS_HAND
	
	def load_help_data(self):
		'''
		Loads help data from the specified help file if possible.
		'''
		
		if self.help_source is None:
			self.log.warning(f"No help file source provided, cannot load help data.")
			return False
		
		try:
			with open(self.help_source) as f:
				self.help_data = json.load(f)
		except Exception as e:
			self.log.error(f"Failed to read help from source >{self.help_source}<. ({e})")
			return False
		
		return True
	
	def load_topic_data(self):
		'''
		Loads topic data from the specified help file if possible.
		'''
		
		def add_full_paths(node:dict, prefix:str=""):
			"""Recursively add a slash-delimited full_path to each topic entry."""
			if not isinstance(node, dict):
				return
			for name, data in node.items():
				if not isinstance(data, dict):
					continue
				full_path = f"TOPICS/{name}" if prefix == "" else f"{prefix}/{name}"
				data["full_path"] = full_path
				subtopics = data.get("subtopics")
				if isinstance(subtopics, dict):
					add_full_paths(subtopics, full_path)
		
		if self.topic_source is None:
			self.log.warning(f"No topic help file source provided, cannot load topic help data.")
			return False
		
		try:
			with open(self.topic_source) as f:
				self.topic_data = json.load(f)
			
			add_full_paths(self.topic_data)
		except Exception as e:
			self.log.error(f"Failed to read topic help from source >{self.topic_source}<. ({e})")
			return False
		
		return True
	
	def connect_socket(self):
		""" Creates a socket and tries to join the server. Must be called
		after the address has already been set with set_addr(). Can be used
		for both initial connections, and reconnecting. """
		
		# Create new socket
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		
		# Connect to socket
		try:
			self.sock.connect(self.addr)
		except:
			self.log.warning("Failed to connect to server")
			return

		
		# Perform handshake
		self.handshake()
	
	def send_command(self, c:GenCommand):
		''' Sends a command object to the server. Receives no response data, only
		pass/fail status. Returns true or false for pass/fail status. '''
		
		# DOESNT CHECK FOR STATE _ ALL VALID
		# # Check for valid state
		# if self.state == ClientAgent.CS_GAME or self.state == ClientAgent.CS_LOGIN:
		# 	logging.warning("Cannot sync prior to login.")
		# 	return False
		
		self.log.debug(f"Sending GenCommand: {c.command}", detail=f"Command data: {c.data}")
		
		# Prepare server for generalized command
		if not self.query("SENDGC"):
			return False
		if self.reply != "ACK":
			logging.warning(f"Did not receive acknowledgement for SENDGC from server. Connection is likely broken! ({self.err()})")
			return False
		
		logging.debug(f"Sending GenCommand: [{c.command}], data={c.data}, meta={c.metadata}")
		
		# Send command data to server - some affirmative/negative response will be returned.
		self.query(c.to_utf8())
		
		if self.reply == "ACK":
			logging.debug("SENDGC was processed on server without incident.")
		else:
			logging.warning(f"Server refused to execute SENDGC. ({self.reply})")
			return False
		
		return True
	
	def query_command(self, c:GenCommand):
		''' Sends a command object to the server as a query. Expects a GenData object back and 
		returns it. Returns None on error.
		'''
		
		# DOESNT CHECK FOR STATE _ ALL VALID
		# # Check for valid state
		# if self.state == ClientAgent.CS_GAME or self.state == ClientAgent.CS_LOGIN:
		# 	logging.warning("Cannot sync prior to login.")
		# 	return False
		
		self.log.debug(f"Querying GenCommand: {c.command}", detail=f"Command data: {c.data}")
		
		# Prepare server for generalized command
		if not self.query("QRYGC"):
			logging.warning(f"Failed to send QRYGC.")
			return None
		if self.reply != "ACK":
			logging.warning(f"Did not receive acknowledgement for QRYGC from server. Connection is likely broken! ({self.err()})")
			return False
		
		# logging.debug(f"Querying GenCommand: [{c.command}], data={c.data}, meta={c.metadata}")
		
		# Send command data to server - some affirmative/negative response will be returned.
		self.send(c.to_utf8())
		
		# Get response as bytes and convert to GenData object
		try:
			data_bytes = self.recv()
			gdata = GenData()
			gdata.from_utf8(data_bytes)
		except:
			self.log.error(f"Failed to convert response to GenData object.")
			return None
		
		# Sanity check gdata
		
		# Return response
		return gdata
	
	def err(self):
		"""Returns the last error code. Returns None if last code already read."""
		
		# Get last code, then reset to None
		ec = self.error_code
		self.error_code = None
		
		if ec == None:
			ec = "--"
		
		return ec
	
	def send(self, x, encode_rule=ENC_AUTO, show_log:bool=True):
		""" Encrypts and sends binary data to the server. If a string is provided,
		it will automatically encode the string unless 'no_encode' is set to true.
		Returns pass/fail status.
		
		Uses AES encryption standard.
		"""
		
		if show_log:
			self.log.debug(f"SEND(): Sending '{x}'")
		
		cipher = AES.new(self.aes_key, AES.MODE_CBC, iv=self.aes_iv)
		
		# Automatically encode strings
		if encode_rule == ENC_AUTO:
			if isinstance(x, str):
				x = x.encode()
		elif encode_rule == ENC_TRUE:
			x = x.encode()
		
		# Encrypt data - produce primary data block
		primary_data_block = cipher.encrypt(pad(x, AES.block_size))
		
		# Create length of primary data block specifier block
		pdb_len = len(primary_data_block) # Get length of primary block
		pdb_len_bytes_needed = (pdb_len.bit_length() + 7) // 8 # Get how many bytes needed to represent that number
		pdb_len_block = pdb_len.to_bytes(pdb_len_bytes_needed, 'big', signed=False) # Convert to bytes
		
		# Create initial byte with length of primary block length specifier
		plb_len = len(pdb_len_block) # Get length of block (should be same as pdb_len_bytes_needed)
		init_byte = plb_len.to_bytes(1, 'big', signed=False) # Create initial byte
		
		# Try to send encrypted message - primary data block
		try:
			self.sock.send(init_byte)
			self.sock.send(pdb_len_block)
			self.sock.send(primary_data_block)
		except socket.error as e:
			self.log.error(f"Failed to send data to server. Closing Connection. ({str(e)})")
			
			# Tell state to reconnect
			self.state = ClientAgent.CS_HAND
			self.user = None
			
			return False

		return True
	
	def send_numlist(self, L:list):
		""" Encodes a numeric list as a string, and sends it to the server. """
		
		s = ""
		for el in L:
			s += f"{el}:"
		
		# Remove last colon
		s = s[:-1]
		
		return self.send(s)
	
	def recv(self):
		"""	Receives and decrypts binary data from the server.
		
		Uses AES encryption standard."""
		
		cipher = AES.new(self.aes_key, AES.MODE_CBC, iv=self.aes_iv)
		
		# Loop until entire packet has been received
		data_raw = bytearray()
		loop_count = 0
		len_block_len = None
		primary_len = None
		while True:
			
			loop_count += 1
			self.log.lowdebug(f"recv: reading from socket. Loop=>{loop_count}<, len(data_raw)=>{len(data_raw)}<, len_block_len=>{len_block_len}<, primary_len=>{primary_len}<", detail=f"data={data_raw}")
			
			# Receive data and add to packet
			data_raw += self.sock.recv(PACKET_SIZE) 
			
			# Abort if data too short
			if len(data_raw) < 3:
				continue
			
			# Get length of length-block
			len_block_len = int.from_bytes(data_raw[0:1], 'big', signed=False)
			
			# Abort if data too short to read length-block
			if len(data_raw) < 1+len_block_len:
				continue
			
			# Get length-block
			primary_len = int.from_bytes(data_raw[1:1+len_block_len], 'big', signed=False)
			
			# Get primary block
			if len(data_raw) == 1+len_block_len+primary_len:
				data_block = data_raw[1+len_block_len:1+len_block_len+primary_len]
				break
			elif len(data_raw) > 1+len_block_len+primary_len:
				self.log.warning(f"recv() received more bytes than were declared in the packet header. This is likely indicative of a low-level error in pyfrost.")
				data_block = data_raw[1+len_block_len:1+len_block_len+primary_len]
				break
			else:
				continue
		self.log.lowdebug("Completed read")
		
		if loop_count > 1:
			self.log.lowdebug(f"Data was split over multiple ({loop_count}) reads.")
		
		# Try to receive encrypted message
		try:
			rv = unpad(cipher.decrypt(data_block), AES.block_size)
		except socket.error as e:
			self.log.error(f"Failed to receive data from server. Closing connection.({str(e)})")
			
			# Tell state to reconnect
			self.state = ClientAgent.CS_HAND
			self.user = None
			
			return None
		except Exception as e:
			self.log.error(f"Failed to receive or decrypt message from server. ({str(e)})")
			return None

		return rv
	
	def recv_str(self):
		""" Receives and decrypts a string from the server."""

		data = self.recv()

		if data is None:
			return None

		try:
			return data.decode()
		except Exception as e:
			self.log.error(f"Encountered an error during decoding in recv_str(). Message: {e}")
			return None
	
	def rsa_send(self, x, encode_rule=ENC_AUTO):
		""" NOTE: This uses RSA encryption and should ONLY be used to exchange AES keys
		as it imposes a length limit on the data.
		
		Encrypts and sends binary data to the server. If a string is provided,
		it will automatically encode the string unless 'no_encode' is set to true.
		Returns pass/fail status.
		"""

		# if not self.online:
		# 	self.log.warning("Cannot send while offline.")
		# 	return False

		# Automatically encode strings
		if encode_rule == ENC_AUTO:
			if isinstance(x, str):
				x = x.encode()
		elif encode_rule == ENC_TRUE:
			x = x.encode()

		# Try to send encrypted message
		try:
			self.sock.send(rsa.encrypt(x, self.server_key))
			# self.sock.send(x)
		except socket.error as e:
			self.log.error(f"Failed to send data to server. Closing Connection. ({str(e)})")
			
			# Tell state to reconnect
			self.state = ClientAgent.CS_HAND
			self.user = None
			
			return False

		return True

	def rsa_recv(self):
		""" NOTE: This should only be used to exchange AES keys.
		
		Receives and decrypts binary data from the server."""

		# if not self.online:
		# 	self.log.warning("Cannot receive while offline.")
		# 	return None

		# Try to receive encrypted message
		try:
			rv = rsa.decrypt(self.sock.recv(PACKET_SIZE), self.private_key)
			# rv = self.sock.recv(PACKET_SIZE)
		except socket.error as e:
			self.log.error(f"Failed to receive data from server. Closing connection.({str(e)})")
			
			# Tell state to reconnect
			self.state = ClientAgent.CS_HAND
			self.user = None
			
			return None
		except Exception as e:
			self.log.error(f"Failed to receive or decrypt message from client. ({str(e)})")
			return None

		return rv

	def set_addr(self, ipaddr, port):
		""" Sets the address to which the class will connect when 'login()' is
		called.
		"""

		self.ipaddr = ipaddr
		try:
			self.port = int(port)
			self.addr = (self.ipaddr, self.port)
		except:
			return False

		return True

	def query(self, x, receive_string:bool=True):
		"""Sends a message to the server agent and saves the reply string to 
		self.reply. If the reply string is an error (begins with ERRROR:), the 
		error code is saved as an int in self.error_code. """
		
		self.log.lowdebug(f"QUERY(): Sending '{x}'")
		
		# Send encrypted message
		if not self.send(x, show_log=False):
			self.log.warning("Query aborted because send failed.")
			return False
		
		# Receive encrypted message and save to 'reply'
		if receive_string:
			self.reply = self.recv_str()
		else:
			self.reply = self.recv()
		
		if self.reply is None:
			self.log.error(f"query returned None. (msg: {x})")
			return False
		
		# self.log.debug(f"QUERY(): Received '{self.reply}'")
		
		# Populate reply_ec if error detected
		if self.reply[0:6] == "ERROR:":
			self.error_code = self.reply[6:]

		return True
	
	def query_liststr(self, L:list):
		""" Query, but sends list data. Returns data still as a string. """
		
		self.log.lowdebug(f"QUERY(): Sending '{L}'")
		
		# Send encrypted message
		if not self.send_numlist(L):
			self.log.warning("Query aborted because send failed.")
			return False
		
		# Receive encrypted message and save to 'reply'
		self.reply = self.recv_str()
		if self.reply is None:
			self.log.error(f"query returned None. (msg: {L})")
			return False
		
		# self.log.debug(f"QUERY(): Received '{self.reply}'")
		
		# Populate reply_ec if error detected
		if self.reply[0:6] == "ERROR:":
			self.error_code = self.reply[6:]

		return True
	
	def exit(self):
		""" Tells the server to drop the connection """
		
		# Check for valid state
		if self.state != ClientAgent.CS_LOGIN:
			self.log.warning("Cannot exit except in LOGIN state.")
			return False
		
		self.log.debug("Exit Process Beginning")

		# # Set online status to false
		# self.online = False
		
		if not self.query("EXIT"):
			self.log.warning("Failed to send EXIT signal")
			return False
		
		if self.reply != "PASS":
			self.log.warning("Server failed to process exit!")
			return False
		
		self.log.info("Successfully exited server.")
		self.state = ClientAgent.CS_LOGIN
		# self.online = False
				
		return True
	
	def logout(self):
		""" Logs the user out, deauthorizing the client to act on their behalf."""
		
		# Check for valid state
		if self.state != ClientAgent.CS_MAIN:
			self.log.warning(f"Cannot logout except in MAIN state. (state = {self.state})")
			return False
		
		if not self.query("LOGOUT"):
			self.log.warning("Failed to send LOGOUT signal")
			return False
		
		if self.reply != "PASS":
			self.log.warning("Server failed to process logout!")
			return False
		
		self.log.info("Successfully logged off server.")
		self.state = ClientAgent.CS_LOGIN
		# self.online = False
		
		self.user = None
		
		return True
				
	def login(self, username:str, password:str):
		""" Execute login sequence.

		It will return true or false depending on if login was successful.
		"""
		
		self.user = None
		
		# Check for valid state
		if self.state != ClientAgent.CS_LOGIN:
			self.log.warning("Cannot login except in LOGIN state.")
			return False
		
		self.log.debug("Login Process Beginning")
		
		# Begin Login sequence, expect request for username and password
		if (not self.query("LOGIN")) or (self.reply != "UNPWD"):
			self.log.debug("Query check for LOGIN failed.")
			
			# self.online = False
			return False

		# Send username and password (encrypted, but not hashed)
		
		# Send username
		if not self.query(username) or self.reply != "ACK":
			
			# self.online = False
			return False
		
		# Send username
		if not self.query(password) or self.reply != "ACK":
			
			# self.online = False
			return False
		
		# Get login status
		if not self.query("STATUS?"):
			
			# self.online = False
			return False
		
		if self.reply == "PASS":
			# self.online = True
			
			self.user = username
			self.state = ClientAgent.CS_MAIN
			
			return True
		else:
			# self.online = False
			return False
	
	def create_account(self, username:str, email:str, password:str):
		""" Creates a new account on the server. """
		
		# Check for valid state
		if self.state != ClientAgent.CS_LOGIN:
			self.log.warning("Cannot create an account except in LOGIN state.")
			return False
		
		# Begin Signup sequence, expect request for email
		if not self.query("SIGNUP") or self.reply != "EMAIL":
			
			# self.online = False
			return False
		
		# Send email username and password (encrypted, but not hashed)
		
		# Send email
		if not self.query(email) or self.reply != "UNPWD":
			
			# self.online = False
			return False
		
		# Send username
		if not self.query(username) or self.reply != "ACK":
			
			# self.online = False
			return False
		
		# Send password
		if not self.query(password) or self.reply != "ACK":
			
			# self.online = False
			return False
		
		# Get login status
		if not self.query("STATUS?"):
			
			# self.online = False
			return False
		
		if self.reply == "PASS":
			# self.online = True
			return True
		else:
			# self.online = False
			return False
		
	def handshake(self):
		""" Performs handshake with server, exchanging keys. Remainder
		of traffic will be encrypted. """
		
		# Check for valid state
		if self.state != ClientAgent.CS_HAND:
			self.log.warning(f"Cannot perform handshake except in CD_HAND state. (state = {self.state})")
			return False
		
		self.log.debug("Initiating handshake")

		# # Set online status to false
		# self.online = False

		# Tell server to begin handshake
		send_ptstring(self.sock, "HS", self.log)

		# Get server private key back
		self.log.debug("Receiving public key")
		self.server_key = rsa.PublicKey.load_pkcs1(self.sock.recv(1024))

		# Send client private key
		self.log.debug("Sending public key")
		self.sock.send(self.public_key.save_pkcs1("PEM"))

		# self.online = True

		# Receive sync packet
		cmd = self.rsa_recv() # This should be void, without this, the sockets will freeze
		
		## At this point, the handshake is complete and comms are encrypted with RSA ####
		
		# Get AES key
		self.rsa_send("AES_KEY")
		self.log.debug("Waiting for RSA key")
		self.aes_key = self.rsa_recv()
		
		# Get AES iv
		self.rsa_send("AES_IV")
		self.log.debug("Waiting for RSA iv")
		self.aes_iv = self.rsa_recv()

		### At this point the AES keys have been exchanged and the handshake is complete
		
		# Update state
		self.state = ClientAgent.CS_LOGIN
		
		self.log.info("Completed handshake")
		
	def view_database(self):
		""" Retrieve the database as a string. Admin only"""
		
		# Check for valid state
		if self.state != ClientAgent.CS_MAIN:
			self.log.warning("Cannot view database except in MAIN state.")
			return None
		
		# query database
		if not self.query("VIEWDB"):
			
			return None
		else:
			return self.reply
	
	def shutdown_server(self):
		""" Retrieve the database as a string. Admin only"""
		
		# Check for valid state
		if self.state != ClientAgent.CS_MAIN:
			self.log.warning("Cannot shutdown server except in MAIN state.")
			return False
		
		# query database
		if not self.query("SHUTDOWN"):
			
			return False
		
		# Return result
		return (self.reply == "PASS")
	
	def delete_account(self, username:str):
		""" Delete the user account for 'username'. Admin only"""
		
		# Check for valid state
		if self.state != ClientAgent.CS_MAIN:
			self.log.warning("Cannot delete accounts except in MAIN state.")
			return False
		
		# Check username is valid before transmitting to server
		if not username_follows_rules(username):
			self.log.warning("Invalid username provided.")
			return False
		
		# query database
		if not self.query("DELUSR"):
			
			return False
		
		# Return result
		if self.reply != "USR":
			
			return False
		
		# query database
		if not self.query(username):
			
			return False
		
		# Return result - Note this will return as 'PASS' even if the user didn't exist
		return (self.reply == "PASS")
	
	def num_user(self):
		""" Gets the number of users currently logged into the server. 
		Returns None if error, else returns number of logged in users.
		"""
		
		# Allow any state
		
		cmd = GenCommand("NUMUSER", {})
		
		# Send command to server
		gdata = self.query_command(cmd)
		
		# Validate returned data
		if not gdata.validate_reply(['STATUS', 'NUMUSER'], self.log):
			return None
		
		# Else return value
		return int(gdata.data['NUMUSER'])
	
	def message_user(self, user:str, message:str):
		
		""" Sends a message to the user (specified by username) """
		
		# Check for valid state
		if self.state == ClientAgent.CS_HAND or self.state == ClientAgent.CS_LOGIN:
			self.log.warning("Cannot message users prior to login.")
			return False
		
		# Check username is valid before transmitting to server
		if not username_follows_rules(user):
			self.log.warning("Invalid username provided.")
			return False
		
		# Verify message doesn't contain unrecognized characters
		filt_msg = validate_message(message)
		
		cmd = GenCommand("MSGUSR", {"RECIP":user, "MSG":filt_msg})
		
		# Check for valid state
		if self.state != ClientAgent.CS_MAIN:
			logging.warning("Cannot send `MSGUSR` instruction outside of CS_MAIN state.")
			return False
		
		# Send command to server
		return self.send_command(cmd)
	
	def sync(self):
		""" Updates local data from the server. Gets messages/notifications, ThreadSafeData, etc """
		
		# Check for valid state
		if self.state == ClientAgent.CS_HAND or self.state == ClientAgent.CS_LOGIN:
			self.log.warning("Cannot sync prior to login.")
			return False
		
		# query database
		if not self.query("SYNC", receive_string=False):
			return False
		
		# Get returned result
		try:
			sd_dict = msgpack.unpackb(self.reply, raw=False)
			sd = from_serial_dict(sd_dict)
		except Exception as e:
			self.log.error(f"Failed to read SyncData ({e})")
			self.log.debug(f"SyncData: {self.reply}")
			return
		
		# print(f"Lobby-serialized: {sd.lobby_serialized} (sd-type={type(sd)}, sd_dict-type={type(sd_dict)})", flush=True)
		# print(f"Connection-state: {sd.connection_state}")
		# print(f"Stowaway: {sd.stowaway}")
		
		try:
			self.notes = sd.notes
			self.lobby = from_serial_dict(sd.lobby_serialized)
			# print(f"Lobby: {self.lobby}")
			self.stowaway = sd.stowaway
			self.connection_state = sd.connection_state
		except Exception as e:
			self.log.warning(f"Failed to populate ClientAgent from SyncData ({e})")
			return

def autosync(ca:ClientAgent):
	''' Automatically syncs data between the server and client. '''
	
	# Sync client with server
	ca.sync()
	
	# Print messages if present
	if len(ca.notes) > 0:
		print(f"Messages:")
	for note in ca.notes:
		print(f"\t{Fore.LIGHTBLACK_EX}({note.timestamp_created}){Fore.YELLOW}[FROM: {note.sender}]{Style.RESET_ALL}{note.msg}")
	ca.notes = []

def commandline_main(ca:ClientAgent, commandline_extended:Callable[[ClientAgent, list ], None]=None) -> None:
	'''
	
		commandline_extended is an optional argument. If provided, it should point to a function that will accept the clientagent, and the client options object, and the list of words. It should return a boolean value, returning true if it recognizes the command 
		and false otherwise.
	
	'''
	
	def sync_from_cli(ca:ClientAgent):
		
		# Execute sync
		ca.sync()
		
		# Print messages if received
		if len(ca.notes) > 0:
			print(f"Messages:")
		for note in ca.notes:
			print(f"\t{Fore.LIGHTBLACK_EX}({note.timestamp_created}){Fore.YELLOW}[FROM: {note.sender}]{Style.RESET_ALL}{note.msg}")
		ca.notes = []
	
	while True:
		
		bracket_color = Fore.LIGHTBLACK_EX
		offline_color = Fore.RED
		menu_color = Fore.WHITE
		game_color = Fore.GREEN
		
		#Get status string:
		if ca.state == ClientAgent.CS_HAND:
			online_string = f"{bracket_color}[{offline_color}OFFLINE{bracket_color}]"
			
		elif ca.state == ClientAgent.CS_LOGIN:
			online_string = f"{bracket_color}[{menu_color}CS_LOGIN{bracket_color}]"
			
		elif ca.state == ClientAgent.CS_MAIN:
			online_string = f"{bracket_color}[{menu_color}CS_MAIN{bracket_color}]"
			
		elif ca.state == ClientAgent.CS_LOBBY:
			online_string = f"{bracket_color}[{game_color}CS_LOBBY{bracket_color}]"
			
		elif ca.state == ClientAgent.CS_GAME:
			online_string = f"{bracket_color}[{game_color}CS_GAME{bracket_color}]"
			
		elif ca.state == ClientAgent.CS_RESULTS:
			online_string = f"{bracket_color}[{game_color}CS_RESULTS{bracket_color}]"
			
		else:
			online_string = f"{bracket_color}[{offline_color}Unknown State{bracket_color}]"
			
		# Get username
		if ca.user is not None:
			user_string = f"{Fore.LIGHTGREEN_EX}{ca.user}"
		else:
			user_string = f"{Fore.YELLOW}No User"
		
		# Main Prompt
		cmd_raw = input(f"{online_string} {user_string}{Fore.GREEN}> {Style.RESET_ALL}")
		words = parse_idx(cmd_raw, " \t")
		
		cmd_code = ensureWhitespace(cmd_raw, "[],")
		words_code = parse_idx(cmd_code, " \t")
		
		if len(words) < 1:
			continue
		cmd = words[0].str
		
		# Individual commands can set this to False if they want to disable
		# autosync
		autosync_eligable = True
		
		if cmd.upper() == "LOGIN":
			un = input("  Username: ")
			pw = getpass("  Password: ")
			if ca.login(un, pw):
				print(f"{Fore.GREEN}Successfully logged in{Style.RESET_ALL}")
			else:
				print(f"{Fore.RED}Failed to log in{Style.RESET_ALL}")
			
			autosync_eligable = False
		elif cmd.upper() == "SIGNUP":
			un = input("  Username: ")
			em = input("     Email: ")
			pw = getpass(prompt="  Password: ")
			
			#TODO: Sends password as plain text! Hashing needs to be done at client side!
			
			if ca.create_account(un, em, pw):
				print(f"{Fore.GREEN}Successfully created account{Style.RESET_ALL}")
			else:
				print(f"{Fore.RED}Failed to create account.{Style.RESET_ALL} Error code #{ca.err()}")
		elif cmd.upper() == "LOGOUT":
			if ca.logout():
				print(f"{Fore.GREEN}Successfully logged out{Style.RESET_ALL}")
				user = None
			else:
				print(f"{Fore.RED}Failed to log out.{Style.RESET_ALL}")
			
			autosync_eligable = False
		elif cmd.upper() == "CLS" or cmd.upper() == "CLEAR":
			if os.name == 'nt':
				os.system("cls")
			else:
				os.system("clear")
		elif cmd.upper() == "CONNECT":
			ca.connect_socket()
			
			autosync_eligable = False
		elif cmd.upper() == "EXIT":
			if ca.exit():
				print("Exited server")
			else:
				print("Failed to exit server")
			break
		elif cmd.upper() == "VIEWDB":
			dbs = ca.view_database()
			if dbs is not None:
				print(dbs)
		elif cmd.upper() == "SHUTDOWN":
			
			confirmation_ans = input(f"{Fore.RED}CONFIRM{Fore.WHITE} - {Style.RESET_ALL} Shutdown server? (y/n)")
			if confirmation_ans.upper() != "Y":
				continue

			dbs = ca.shutdown_server()
			if dbs:
				print("Server shutting down")
			else:
				print("Failed to shut down server")
		elif cmd.upper() == "DELUSR":
			
			# Check for number of arguments
			if len(words) < 2:
				print(f"{Fore.LIGHTRED_EX}Command DELUSR requires 1 or more arguments (Username to delete){Style.RESET_ALL}")
				continue
			
			# List all users to delete and get confirmation
			print(f"{Fore.LIGHTRED_EX}Users to delete:{Style.RESET_ALL}")
			for usr in words[1:]:
				print(f"\t{Fore.LIGHTRED_EX}USER: {Style.RESET_ALL}{usr.str}")
			confirmation_ans = input(f"{Fore.RED}CONFIRM{Fore.WHITE} - {Style.RESET_ALL} Delete following user(s)? (y/n)")	
			if confirmation_ans.upper() != "Y":
				continue
			
			# Delete account(s)
			for usr in words[1:]:
				ca.delete_account(usr.str)
		
		elif cmd.upper() == "MSGUSR":
			
			# Check for number of arguments
			if len(words) < 3:
				print(f"{Fore.LIGHTRED_EX}Command MSGUSR requires 2 or more arguments (Username to message, message to send (in double quotes)){Style.RESET_ALL}")
				continue
			
			msg = cmd_raw[words[2].idx:]
			if msg[0] != "\"" or msg[-1] != "\"":
				print(f"{Fore.LIGHTRED_EX}Command MSGUSR - message must be contained in double quotes){Style.RESET_ALL}")
				continue
			
			# Send message
			ca.message_user(words[1].str, msg)
			
			# # Autosync
			# if opt.cli_autosync:
			# 	autosync(ca)
		
		elif cmd.upper() == "NUMUSER":
			
			# Execute command
			nu = ca.num_user()
			if nu is None:
				print(f"\t{Fore.RED}Error occured while attempting to read number of users.{Style.RESET_ALL}")
			else:
				print(f"\tNumber of users logged into server: {Fore.YELLOW}{nu}{Style.RESET_ALL}")
			
		elif cmd.upper() == "SYNC":
			
			# Run sync and print messages
			sync_from_cli(ca)
			autosync_eligable = False
		
		elif cmd.upper() == "RELOADHELP":
			
			if ca.load_help_data():
				print(f"\t{Fore.GREEN}Reloaded help data from disk.{Style.RESET_ALL}")
			else:
				print(f"\t{Fore.RED}Failed to reload help data from disk.{Style.RESET_ALL}")
			
			if ca.load_topic_data():
				print(f"\t{Fore.GREEN}Reloaded topic-help data from disk.{Style.RESET_ALL}")
			else:
				print(f"\t{Fore.RED}Failed to reload topic-help data from disk.{Style.RESET_ALL}")
		
		elif cmd.upper() == "HELP":
			
			HELP_WIDTH = 80
			TABC = "    "
			
			color1 = Fore.WHITE # Body text
			color2 = Fore.LIGHTYELLOW_EX # Titles/headers
			color3 = Fore.YELLOW # Type specifiers, etc
			color4 = Fore.LIGHTBLACK_EX # brackets and accents
			
			hstr = ""
			
			list_commands = False
			list_topics = False
			
			# Check for flags
			print_long = False
			if len(words) > 1:
				for tk in words:
					tks = tk.str.lower()
					if tks == "-l" or tks == "--list":
						list_commands = True
					if tks == "-t" or tks == "--topic":
						list_topics = True
			
			
			if list_commands:
				
				# title
				hstr += color2 + "-"*HELP_WIDTH + Style.RESET_ALL + "\n"
				hstr += color2 + barstr(f"ALL COMMANDS", HELP_WIDTH, "-", pad=True) + Style.RESET_ALL + "\n\n"
				
				for cmd in ca.help_data.keys():
					desc = ca.help_data[cmd]['description']
					hstr += f"{TABC}{Fore.CYAN}{cmd}{color1}: {desc}\n"
				
				print(hstr)
				continue
			
			def print_topic_level(name, data, indent:int=1, max_indent:int=4):
				
				tab_level = TABC*indent
				
				desc = data['description']
				print(f"{tab_level}{Fore.CYAN}{name}{color1}: {desc}{Style.RESET_ALL}")
				
				# Handle subtopics
				if 'subtopics' in data.keys() and len(data['subtopics']) > 0:
					
					# Expand...
					if indent < max_indent:
						for st in data['subtopics'].keys():
							print_topic_level(st, data['subtopics'][st], indent+1, max_indent)
					else:
						print(f"{TABC*(indent+1)}...")

			def find_topic(path:str):
				"""Returns the topic node for a slash-delimited path (e.g. RULES/QUORUM).
				Also resolves matches that omit leading sections (e.g. OCCUPATION/QUORUM).
				
				Returns:
					tuple: index 0: node that matched or None if nothing found. Index 1: bool indicating if this explicitly a topic search.
				"""
				
				def match_from_node(node, segments, idx):
					"""Walk down from the current node following remaining segments."""
					if idx == len(segments):
						return node
					
					subtopics = node.get("subtopics", {})
					if not isinstance(subtopics, dict):
						return None
					
					next_seg = segments[idx]
					if next_seg not in subtopics:
						return None
					
					return match_from_node(subtopics[next_seg], segments, idx+1)
				
				def search_topics(topic_map, segments, idx):
					"""Depth-first search for a path starting at any node."""
					for name, data in topic_map.items():
						# Try matching starting at this node
						if name == segments[idx]:
							match = match_from_node(data, segments, idx+1)
							if match is not None:
								return match
						
						# Continue searching deeper even if the current name doesn't match
						subtopics = data.get("subtopics", {})
						if isinstance(subtopics, dict):
							match = search_topics(subtopics, segments, idx)
							if match is not None:
								return match
					
					return None
				
				# Break into segments
				segments = [seg.upper() for seg in path.split("/") if seg != ""]
				
				# Return if no segments present
				if len(segments) == 0:
					return (None, False)
				
				# If TOPIC or TOPICS is first segment, remove, and indicate this is explictly
				# a topic and not a command.
				is_explicit = False
				if (segments[0] == 'TOPICS') or (segments[0] == 'TOPIC'):
					is_explicit = True
					segments = segments[1:]
					
					# Return if no segments present
					if len(segments) == 0:
						return (None, True)
				
				# Perform search
				return (search_topics(ca.topic_data, segments, 0), is_explicit)
			
			if list_topics:
				
				# title
				hstr += color2 + "-"*HELP_WIDTH + Style.RESET_ALL + "\n"
				hstr += color2 + barstr(f"ALL TOPICS", HELP_WIDTH, "-", pad=True) + Style.RESET_ALL + "\n\n"
				
				print(hstr)
				
				for cmd in ca.topic_data.keys():
					print_topic_level(cmd, ca.topic_data[cmd], 1, 4)
				
				continue
			
			# Check for number of arguments
			if len(words) < 2:
				hcmd = "HELP"
			else:
				hcmd = words[1].str.upper()
			
			cmd_list = ca.help_data.keys()
			(topic_entry, explicitly_topic) = find_topic(hcmd)
			# topic_path = words[1].str if len(words) > 1 else hcmd
			
			if (hcmd in cmd_list) and (not explicitly_topic): # HCMD is a COMMAND name
			
				## Print help data:
				try:
					# title
					hstr += color2 + "-"*HELP_WIDTH + Style.RESET_ALL + "\n"
					hstr += color2 + barstr(f"{hcmd} Help", HELP_WIDTH, "-", pad=True) + Style.RESET_ALL + "\n\n"
					
					# Description
					hstr += f"{color2}Description:\n"
					hstr += f"{color1}{TABC}" + ca.help_data[hcmd]['description']+Style.RESET_ALL + "\n"
					
					# Arguments
					if len(ca.help_data[hcmd]['arguments']) > 0:
						hstr += f"{color2}\nArguments:\n"
						for ar in ca.help_data[hcmd]['arguments']:
							
							arg_name = ar['name']
							if ar['type'] in ["num", "str", "list", "cell", "list[cell]"]:
								type_name = ar['type']
							else:
								type_name = f"{Fore.RED}???"
							
							if ar['optional']:
								hstr += TABC + f"{color4}( {color1}{arg_name} {color4}[{color3}{type_name}{color4}]) "
							else:
								hstr += TABC + f"{color4}< {color1}{arg_name} {color4}[{color3}{type_name}{color4}]> "
							
							hstr += color1 + ar['description'] + "\n"
					
					# Flags
					if len(ca.help_data[hcmd]['flags']) > 0:
						hstr += f"{color2}\nFlags:\n"
						for ar in ca.help_data[hcmd]['flags']:
							
							if ar["short"] != "" and ar["long"] != "":
								hstr += TABC + color1 + ar['short'] + f"{color4}," + color1 + ar["long"] + color4 + ": "
							elif ar['short'] != "":
								hstr += TABC + color1 + ar['short'] + color4 + ": "
							else:
								hstr += TABC + color1 + ar['long'] + color4 + ": "
								
							
							hstr += color1 + ar['description'] + "\n"
					
					# Examples
					if len(ca.help_data[hcmd]['examples']) > 0:
						hstr += f"{color2}\nExamples:\n"
						for ex_no, ar in enumerate(ca.help_data[hcmd]['examples']):
							
							hstr += f"{color1}{TABC}Ex {ex_no}:\n"
							hstr += TABC + TABC + color4 + ">> " + color3 + ar['command'] + "\n"
							hstr += TABC + TABC + color1 + "Desc: " + color1 + ar['description'] + "\n"
						
						hstr += "\n"
					
					
					# See also
					if len(ca.help_data[hcmd]['see_also']) > 0:
						hstr += f"{color2}\nSee Also:\n{TABC}{color1}"
						add_comma = False
						for ar in ca.help_data[hcmd]['see_also']:
							
							if ar.upper() in cmd_list:
								
								if add_comma:
									hstr += ", "
								
								hstr += ar
								add_comma = True
					
					print(hstr)
				except Exception as e:
					print(f"Corrupt help data for selected entry '{hcmd}' ({e}).")
					
			elif topic_entry is not None: # HCMD is a TOPIC name
					
					print("Printing topic data")
					
					
					## Print help data:
					try:
						
						short_name = topic_entry['full_path'].rsplit("/", 1)[-1]
						full_name = topic_entry['full_path']
						
						# title
						hstr += color2 + "-"*HELP_WIDTH + Style.RESET_ALL + "\n"
						hstr += color2 + barstr(f"{short_name} Help", HELP_WIDTH, "-", pad=True) + Style.RESET_ALL + "\n"
						hstr += f"{color1}Full name: {full_name}\n\n"
						
						# Description
						hstr += f"{color2}Description:\n"
						hstr += f"{color1}{TABC}" + topic_entry.get('description', '')+Style.RESET_ALL + "\n"
						
						# Body
						body = topic_entry.get('body', [])
						if len(body) > 0:
							hstr += f"{color2}\nDetails:\n"
							for section in body:
								text = section.get('data', '')
								section_type = section.get('type', 'paragraph')
								if section_type != "paragraph":
									hstr += f"{color4}{TABC}[{section_type}]{Style.RESET_ALL}\n"
								hstr += f"{color1}{TABC}{text}{Style.RESET_ALL}\n\n"
						
						# Subtopics
						subtopics = topic_entry.get('subtopics', {})
						if isinstance(subtopics, dict) and len(subtopics) > 0:
							hstr += f"{color2}Subtopics:\n"
							for name, data in subtopics.items():
								desc = data.get('description', '')
								hstr += f"{TABC}{Fore.CYAN}{name}{color1}: {desc}\n"
						
						# See also
						if len(topic_entry.get('see_also', [])) > 0:
							hstr += f"{color2}\nSee Also:\n{TABC}{color1}"
							add_comma = False
							for ar in topic_entry.get('see_also', []):
								
								if add_comma:
									
									hstr += ", "
								
								hstr += ar
								add_comma = True
						
						print(hstr)
					except Exception as e:
						print(f"Corrupt help data for selected entry '{hcmd}' ({e}).")
		elif cmd.upper() == "CLIENTSETTINGS":
			
			# Run settings menu
			ca.settings_manager.run()
			
		else:
			
			# Check if custom handler is implemented and recognizes command
			if commandline_extended is not None:
				found_cmd = commandline_extended(ca, words)
			else:
				found_cmd = False
			
			# If command wasn't found, print error
			if not found_cmd:
				print(f"    Failed to recognize command {Fore.BLUE}<{Fore.YELLOW}{cmd}{Fore.BLUE}>{Style.RESET_ALL}")
		
		# Autosync
		if autosync_eligable and ca.settings_manager.get('autosync-post-command'):
			sync_from_cli(ca)
		
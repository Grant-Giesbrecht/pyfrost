import socket
import rsa
import tabulate
import threading
import hashlib
import sqlite3
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from pylogfile import *
from pyfrost.pyfrost import *

# Initialize database access
db_mutex = threading.Lock() # Create a mutex for the database

ENC_FALSE = 100
ENC_AUTO = 101
ENC_TRUE = 102

class ClientAgent:
	""" This class handles networking for the client. It communicates with the
	server and handles encryption and login.
	"""
	
	# Client State Objects
	CS_HAND = 1 # Need to perform handshake - not encrypted. Perhaps not connected to server.
	CS_LOGIN = 2 # At login/signup phase - not authorized
	CS_MAIN = 3 # Connected to server, can perform primary operations
	
	def __init__(self, log:LogPile, address:str=None, port:int=None):
		
		# Save log object
		self.log = log
		
		self.sock = None
		self.ipaddr = address
		self.port = port
		self.addr = (self.ipaddr, self.port)
		
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
		
		self.sharedata = ShareData()
		
		self.state = ClientAgent.CS_HAND
	
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
	
	def err(self):
		"""Returns the last error code. Returns None if last code already read."""
		
		# Get last code, then reset to None
		ec = self.error_code
		self.error_code = None
		
		if ec == None:
			ec = "--"
		
		return ec
	
	def send(self, x, encode_rule=ENC_AUTO):
		""" Encrypts and sends binary data to the server. If a string is provided,
		it will automatically encode the string unless 'no_encode' is set to true.
		Returns pass/fail status.
		
		Uses AES encryption standard.
		"""
		
		cipher = AES.new(self.aes_key, AES.MODE_CBC, iv=self.aes_iv)
		
		# Automatically encode strings
		if encode_rule == ENC_AUTO:
			if isinstance(x, str):
				x = x.encode()
		elif encode_rule == ENC_TRUE:
			x = x.encode()

		# Try to send encrypted message
		try:
			self.sock.send(cipher.encrypt(pad(x, AES.block_size)))
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
		
		# Try to receive encrypted message
		try:
			rv = unpad(cipher.decrypt(self.sock.recv(PACKET_SIZE)), AES.block_size)
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

	def query(self, x):
		"""Sends a message to the server agent and saves the reply string to 
		self.reply. If the reply string is an error (begins with ERRROR:), the 
		error code is saved as an int in self.error_code. """
		
		self.log.debug(f"QUERY(): Sending '{x}'")
		
		# Send encrypted message
		if not self.send(x):
			self.log.warning("Query aborted because send failed.")
			return False
		
		# Receive encrypted message and save to 'reply'
		self.reply = self.recv_str()
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
		
		self.log.debug(f"QUERY(): Sending '{L}'")
		
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
		
		# Send message
		if not self.query("MSGUSR"):
			self.log.warning(f"Failed to send MSGUSR signal ({self.err()})")
			return False
		
		if self.reply != "USR":
			self.log.warning(f"Server failed to process MSGUSR ({self.err()})")
			return False
		
		# Send recipient name
		if not self.query(user):
			self.log.warning(f"Failed to send MSGUSR signal ({self.err()})")
			return False
		
		if self.reply != "MSG":
			self.log.warning(f"Server failed to process MSGUSR ({self.err()})")
			return False
		
		# Send message
		if not self.query(filt_msg):
			self.log.warning(f"Failed to send MSGUSR signal ({self.err()})")
			return False
		
		if self.reply != "PASS":
			self.log.warning(f"Server failed to process message in MSGUSR exchange ({self.err()})")
			return False
	
	def sync(self):
		""" Updates local data from the server. Gets messages/notifications, ShareData, etc """
		
		# Check for valid state
		if self.state == ClientAgent.CS_HAND or self.state == ClientAgent.CS_LOGIN:
			self.log.warning("Cannot sync prior to login.")
			return False
		
		# query database
		if not self.query("SYNC"):
			return False
		
		# Get returned result
		try:
			sd = SyncData()
			sd.from_utf8(self.reply.encode()) #TODO: This is repetative! query automatically decodes, but from_utf8 wants it encoded again!
		except Exception as e:
			self.log.error(f"Failed to read SyncData ({e})")
			self.log.debug(f"SyncData: {self.reply}")
			return
		
		###### NOw we have the JSON data saved in JD. Turn it into a SyncData object #######
		
		# Transfer data from SyncData object to ClientAgent object
		try:
			self.notes = sd.notes
			self.sharedata.unpack(sd.packed_sharedata)
		except Exception as e:
			self.log.warning(f"Failed to populate ClientAgent from SyncData ({e})")
			return
		
		#TODO: Can you sync ClientAgent state from ShareData state?
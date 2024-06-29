import socket
import threading

from colorama import Fore, Style, Back

from pyfrost.pyfrost import *

import copy
import rsa
import hashlib
import sqlite3
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from dataclasses import dataclass
import time

# Initilize global variable - thread counter
next_thread_id = 0 # This is NOT protected by a mutex and should only ever be modified or read from the main thread

# TODO: Make this configurable and not present in most client copies
DATABASE_LOCATION = "userdata.db"

# Variable that tells server to continue to run
@dataclass
class ServerOptions:
	server_running = True
	kill_stat_thread = False
	kill_distribution_thread = False
	kill_garbage_thread = False
server_opt = ServerOptions()

# Class used to contain the last time a thread was responsive. Is
# used to check if a thread is frozen/crashed and should be ignored
#
# Is a class instead of scalar so value can change without changing address
@dataclass
class LastUpdateTime:
	t = time.time()

@dataclass
class DirectoryEntry:
	""" Class that contains *address sensitive* user data. """
	
	t = None # Last Update Time. This is a pulse to see if the client thread is still active
	
	note_list = None # This is the user's note list. You must use the user's note_mutex to access it!
	note_mutex = None # This is the mutex to protect the user's note list

# Account type constants
KONTO_STANDARD = 'STANDARD' # Standard account
KONTO_TRIAL = 'TRIAL' # Trial account
KONTO_ADMIN = 'ADMIN' # Administrator account

# Master mutex protects the lists: 'sharedata_objects' and 'sharedata_mutexes'
master_mutex = threading.Lock()
sharedata_objects = [] # This will hold all the sharedata objects (This is a pool of data shared between mult clients and sync'd via the server.)
sharedata_mutexes = [] # This will hold all the mutexes for each sharedata obejct

# Distribution mutex protects the distribution inbox
distribution_mutex = threading.Lock()
distribution_inbox = [] # List of incoming notifications for the distribution thread to pass to each user

# The directory mutex is used to lock the user directory
directory_mutex = threading.Lock()
user_directory = {} # This will hold tuples of user note lists and their mutexes

# Initialize database access
db_mutex = threading.Lock() # Create a mutex for the database

# next_lobby_id can be accessed by any ServerAgent thread, so it must always
# be accessed through the lobby_id_mutex
lobby_id_mutex = threading.Lock()
next_lobby_id = 0

class ServerAgent (threading.Thread):
	""" Each instance of this class will live in a separate thread on the server. It
	doesn't model a user/client, but an instance of a user/client
	connecting to the server. As such, it uses the client account_id to identify
	itself.
	
	It also is responsible for understanding who's account the client is authorized 
	to access, and that account's access level (standard, admin, etc). This is the
	level where those security blocks will appear (ie. if not admin, these functions
	will block acess).
	"""
	
	# Thread State Constants
	TS_HAND = 1 # Need to perform handshake - not encrypted yet
	TS_LOGIN = 2 # Client not yet authorized, needs to login or create account
	TS_MAIN = 3 # Client authorized, at main loop
	TS_EXIT = 0 # Exit main loop, close thread
	
	def __init__(self, sock, thread_id, log:LogPile):
		
		super().__init__()
		
		# Captures which screen/state the client should be in and what type of
		# commands server should be ready for
		self.state = ServerAgent.TS_HAND

		# Client user data
		self.auth_user = None # This will have username of user who has been authorized as loged in
		self.acct_id = None # CLient account ID
		self.usr_type = None # type of account

		# Socket object from connecting to client program
		self.sock = sock
		
		# Log object
		self.log = log

		# Generate keys and AES cipher
		self.public_key, self.private_key = rsa.newkeys(1024)
		self.aes_key = get_random_bytes(AES_KEY_SIZE)
		
		temp_cipher = AES.new(self.aes_key, AES.MODE_CBC)
		self.aes_iv = temp_cipher.iv

		# Server's public key
		self.client_key = None
		
		# Error code from last failed operation (Will be filled with ERR_ codes). Access with err()
		self.error_code = None
		self.last_update_time = LastUpdateTime()
		
		# Create database object
		self.db = UserDatabase(DATABASE_LOCATION)
		
		# Multithreading variables
		self.thread_id = thread_id
		self.id_str = f"{Fore.LIGHTMAGENTA_EX}[T-ID: {Fore.WHITE}{self.thread_id}{Fore.LIGHTMAGENTA_EX}]{Style.RESET_ALL} " # Thread ID string for each logging message
		
		# These will point to a sharedata and mutex in the main 'sharedata' and 'sharedata_mutexes'
		# lists. Use sharedata_mutex prior to modifying the sharedata object.
		self.sharedata = ShareData()
		self.sharedata_mutex = None
		
		# The notes array contains any incoming notifications or messages. It will be modified
		# by the distribution thread, so be sure to always use the mutex before checking/modifying it.
		self.notes = []
		self.notes_mtx = threading.Lock()
		
	def set_auth_user(self, user:str):
		"""Accepts the username of an authorized user and configures the object to reflect that user."""
		global user_directory, directory_mutex
		
		# Add client to directory
		with directory_mutex:
			
			# Create new directory entry and populate
			de = DirectoryEntry()
			de.note_list = self.notes
			de.note_mutex = self.notes_mtx
			de.t = self.last_update_time
			
			# Add to user_directory
			if user in user_directory:
				user_directory[user].append(de)
			else:
				user_directory[user] = [de]
		
		# Remove user authorization
		self.auth_user = user
		self.acct_id = self.db.get_user_id(user)
		self.usr_type = self.db.get_user_type(user)
		
	def err(self):
		"""Returns the last error code. Returns None if last code already read."""
		
		# Get last code, then reset to None
		ec = self.error_code
		self.error_code = None
		
		return ec

	def send(self, x, no_encode=False):
		""" Encrypts and sends binary data to the client. If a string is provided,
		it will automatically encode the string unless 'no_encode' is set to true.
		Returns pass/fail status.
		"""
		
		cipher = AES.new(self.aes_key, AES.MODE_CBC, iv=self.aes_iv)
		
		# Automatically encode strings
		if isinstance(x, str) and (not no_encode):
			x = x.encode()

		# Try to send encrypted message
		try:
			self.sock.send(cipher.encrypt(pad(x, AES.block_size)))
		except socket.error as e:
			self.log.error(f"{self.id_str}Failed to send data to client. ({str(e)})")
			return False

		return True
		
	def recv(self):
		""" Receives and decrypts binary data from the client using AES encryption."""
		
		cipher = AES.new(self.aes_key, AES.MODE_CBC, iv=self.aes_iv)
		
		# Try to receive encrypted message
		try:
			rv = unpad(cipher.decrypt(self.sock.recv(PACKET_SIZE)), AES.block_size)

		except socket.error as e:
			self.log.error(f"{self.id_str}Failed to receive data from client. ({str(e)}). Closing connection.")
			
			# Logout the client and prepare to exit
			self.prepare_exit()
			self.logout()
			
			return None
		except Exception as e:
			self.log.error(f"{self.id_str}Failed to receive or decrypt message from client. Closing conection. ({str(e)})")
			
			# Logout the client and prepare to exit
			self.prepare_exit()
			self.logout()
			
			return None

		return rv
	
	def recv_str(self):
		""" Receives and decrypts a string from the client with AES encryption."""
		
		# Receive data
		data = self.recv()
		
		if data is None:
			return None
		
		try:
			data = data.decode()
			return data
		except Exception as e:
			self.log.warning(f"{self.id_str}Exception occured during recv_str() decode. Closing connection. Message {e}")
			
			# Logout the client and prepare to exit
			self.prepare_exit()
			self.logout()
			
			return None
	
	def recv_numlist(self):
		""" Receives and decrypts a list of numbers from the client with AES encryption. """
		
		s = self.recv_str()
		data = []
		
		running = True
		while running:
			
			try:
				idx = s.index(':') # Find index
				ss = s[:idx] # Get substring
				s=s[idx+1:] # Shorten s
			except:
				running = False
				ss = s
			
			try:
				data.append(float(ss))
			except:
				self.warning("Failed to read list data")
				return []
		
		return data
		
	def rsa_send(self, x, no_encode=False):
		""" Encypts data using RSA encryption. NOTE: This has a length limit. For
		most all communications, use AES encryption with 'send()', not 'rsa_send()'. 
		AES encryption will bypass the length limit.
		
		Encrypts and sends binary data to the client. If a string is provided,
		it will automatically encode the string unless 'no_encode' is set to true.
		Returns pass/fail status.
		"""

		# Automatically encode strings
		if isinstance(x, str) and (not no_encode):
			x = x.encode()

		# Try to send encrypted message
		try:
			self.sock.send(rsa.encrypt(x, self.client_key))
			# self.sock.send(x)
		except socket.error as e:
			self.log.error(f"{self.id_str}Failed to send data to client. ({str(e)})")
			return False

		return True

	def rsa_recv(self):
		""" Receives and decrypts binary data from the client using RSA encryption. NOTE: You
		should use 'recv()' most of the time, as AES encryption is used for all but exchanging
		AES keys."""

		# Try to receive encrypted message
		try:
			rv = rsa.decrypt(self.sock.recv(PACKET_SIZE), self.private_key)
			# rv = self.sock.recv(PACKET_SIZE)

		except socket.error as e:
			self.log.error(f"{self.id_str}Failed to receive data from client. ({str(e)}). Closing connection.")
			
			# Logout the client and prepare to exit
			self.prepare_exit()
			self.logout()
			
			return None
		except Exception as e:
			self.log.error(f"{self.id_str}Failed to receive or decrypt message from client. Closing conection. ({str(e)})")
			
			# Logout the client and prepare to exit
			self.prepare_exit()
			self.logout()
			
			return None

		return rv

	def rsa_recv_str(self):
		""" Receives and decrypts a string from the client with RSA encryption."""

		data = self.rsa_recv()

		if data is None:
			return None

		try:
			data = data.decode()
			return data
		except Exception as e:
			self.log.warning(f"{self.id_str}Exception occured during recv_str() decode. Closing connection. Message {e}")
			
			# Logout the client and prepare to exit
			self.prepare_exit()
			self.logout()
			
			return None
	
	def check_valid_password(self, password):
		"""This verifies that the password is sufficiently secure (for use during signup)."""
		
		# Make sure password is 8+ characters
		if len(password) < 8:
			self.error_code = "ERR BAD PASSWORD"
			return False
		
		return True
	
	def check_valid_username(self, username):
		"""Checks if a given string is a valid and unclaimed username. This includes being comprised of the
		correct characters and is not already taken by another user in the database."""
		
		# Check validity of name
		if not username_follows_rules(username): 
			self.error_code = "ERR BAD USERNAME"
			return False
		
		# Aquire mutex to protect database
		with db_mutex:
			
			conn = sqlite3.connect("userdata.db")
			cur = conn.cursor()
			
			# Check for user
			cur.execute("SELECT * FROM userdata WHERE username = ?", (username,))
			if cur.fetchall():
				self.error_code = "ERR TAKEN USERNAME"
				return False
			else:
				return True
			
	def check_valid_email(self, email_addr:str):
		"""Checks if a given email address is a valid and unclaimed address"""
		
		# Check validity of name
		regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
		if not re.fullmatch(regex, email_addr):
			self.error_code = "ERR BAD EMAIL"
			return False
		
		# Aquire mutex to protect database
		with db_mutex:
			
			conn = sqlite3.connect("userdata.db")
			cur = conn.cursor()
						
			# Check for user
			cur.execute("SELECT * FROM userdata WHERE email_addr = ?", (email_addr,))
			if cur.fetchall():
				self.error_code = "ERR TAKEN EMAIL"
				return False
			else:
				return True
			
	def check_login(self, username, password):
		"""  Accepts a username and password and checks if it matches an acct
		in the database.
		"""
		
		# Aquire mutex to protect database
		with db_mutex:
			
			# Connect to the database
			# conn = sqlite3.connect(DATABASE_LOCATION)
			# cur = conn.cursor()
			
			# Get has of password
			password_hash = hashlib.sha256(password.encode()).hexdigest()
			
			conn = sqlite3.connect("userdata.db")
			cur = conn.cursor()
			
			# cur.execute("SELECT * FROM userdata WHERE username = ? AND password = ?", (username, password))	
			
			# Lookup a match
			cur.execute("SELECT * FROM userdata WHERE username = ? AND password = ?", (username, password_hash))
			if cur.fetchall():
				return True
			else:
				return False

	def add_account(self, username:str, password:str, email:str, new_usr_class:int=KONTO_STANDARD):
		""" Creates a new account in the database with specified information """
		
		# Only admin can create non-standard accounts
		if self.usr_class != KONTO_ADMIN:
			new_usr_class = KONTO_STANDARD
		
		# Add to database
		self.db.add_user(username, password, email, new_usr_class)

	def run(self):
		""" Main loop. Engages when the thread is started. """
		
		# count = 5
		
		# Run main loop
		while self.state != ServerAgent.TS_EXIT:
			
			# count -= 1
			
			self.log.debug(f"{self.id_str}Restarting loop. State = {self.state}")
			
			# if count <= 0:
			# 	print("exceeded count limit")
			# 	break
			
			self.main_loop()
	
	def main_loop(self):
		""" This is the function called by the main loop that is run while this thread is active. It
		calls other functions from this class.
		"""
		global server_opt
		
		if self.state == ServerAgent.TS_HAND: # Perform handshake
			
			# Get requested operation from client
			cmd = get_ptstring(self.sock)
			
			# Login handshake
			if cmd != "HS":
				return False
			
			self.log.debug(f"{self.id_str}Sending public key")
			
			# Send server public key
			try:
				self.sock.send(self.public_key.save_pkcs1("PEM"))
			except:
				return False
			
			
			self.log.debug(f"{self.id_str}Receiving public key")
			# Get client public key
			try:
				self.client_key = rsa.PublicKey.load_pkcs1(self.sock.recv(1024))
			except:
				return False
			
			self.log.debug(f"{self.id_str}Sending sync packet")
			self.rsa_send("Void") # This has to be sent, otherwise the sockets lock up!
			
			### Now RSA keys have been exchanged and all comms can be encrypted ####
			
			# Get message from client
			cmd = self.rsa_recv_str()
			self.log.debug(f"{self.id_str}Received string {cmd}")
			if cmd != "AES_KEY":
				return False
			
			# Send AES key (encrypted with RSA)
			self.log.debug(f"{self.id_str}Sending AES key {self.aes_key}")
			self.rsa_send(self.aes_key, False)
			
			# Get message from client
			cmd = self.rsa_recv_str()
			if cmd != "AES_IV":
				return False
			
			self.log.debug(f"{self.id_str}Sending AES iv")
			self.rsa_send(self.aes_iv)
			
			### Now AES keys have been exchanged and large data can be encrypted ###
			
			# Change state
			self.state = ServerAgent.TS_LOGIN
			
			self.log.info(f"{self.id_str}Completed handshake")
			
		elif self.state == ServerAgent.TS_LOGIN:
			
			# Interpret client request
			
			cmd = self.recv_str()

			if cmd == "LOGIN": # Login sequence
				
				# Request username and password
				self.send("UNPWD")
				
				# Receive both -------------------------
				username = self.recv_str()
				self.send("ACK")
				
				password = self.recv_str()
				self.send("ACK")
				
				self.recv_str() #Should be "status?"
				
				# Check login credentials
				if self.check_login(username, password):
					
					# Authorize this client thread for this user
					self.set_auth_user(username)
					
					# Send success reply
					self.send("PASS")
					self.state = ServerAgent.TS_MAIN
					self.log.info(f"{self.id_str}Successfully logged in user: {username}")
				else:
					
					# Send fail reply
					self.send("FAIL")
					self.log.info(f"{self.id_str}Failed to log in user")
			
			elif cmd == "SIGNUP": # Signup new user
				
				self.send("EMAIL")
				
				# Receive and check email
				email = self.recv_str()
				# Check if requested username is valid
				if not self.check_valid_email(email): # Email Failed
					ec = self.err() # Get error code
					# Send error code and get ack
					self.send(f"ERROR:{ec}")
					return
				
				# Request username and password
				self.send("UNPWD")
				
				# Receive and check Username
				username = self.recv_str()
				if not self.check_valid_username(username): # Username Failed
					ec = self.err() # Get error code
					# Send error code and get ack
					self.send(f"ERROR:{ec}")
				self.send("ACK")
				
				# Receive and check password
				password = self.recv_str()
				if not self.check_valid_password(password): # password Failed
						ec = self.err() # Get error code
						# Send error code and get ack
						self.send(f"ERROR:{ec}")
						self.recv() # Ignore this sync packet
				self.send("ACK")
				
				self.recv_str() #Should be "status?"
				
				# Add client to database!
				if self.add_account(username, password, email):
					
					# Authorize for the new user
					self.auth_user = username
					self.state = ServerAgent.TS_MAIN
					
					self.log.info(f"{self.id_str}Added user")
					self.send("PASS")
				else:
					self.log.info(f"{self.id_str}Failed to add user")
					self.send("FAIL")
					
			elif cmd == "EXIT": # Close thread
				
				self.log.info(f"{self.id_str}Client exited server. Shutting down.")
				
				# Mark client to close
				self.prepare_exit()
				
				self.send("PASS")
				
				exit()
		
		elif self.state == ServerAgent.TS_MAIN:
			
			# Get input
			cmd = self.recv_str()
			
			# Match command
			if cmd == "GENCMD":
				
				# Send ack
				self.send("ACK")
				
				# Receive command
				data_bytes = self.recv()
				gc = GenCommand()
				gc.from_utf8(data_bytes)
				
				# Execute command
				if self.execute_gc(gc):
					self.send("ACK")
				else:
					self.send(f"SERVFAIL:")
				
			elif cmd == "LOGOUT":
				
				# Logout
				self.logout()
				
				# Send back to login state
				self.state = ServerAgent.TS_LOGIN
				
				self.send("PASS")
				
			elif cmd == "VIEWDB":
				
				# Only admins may view database
				if self.usr_type != KONTO_ADMIN:
					self.send("Access denied")
					return
				
				# Return database string
				self.send(self.db.view_database())
			
			elif cmd == "SHUTDOWN":
				
				# Only admins may view database
				if self.usr_type != KONTO_ADMIN:
					self.send("ERROR:Access denied")
					return
				
				# Return database string
				server_opt.server_running = False
				
				self.send("PASS")
			
			elif cmd == "DELUSR":
				
				# Only admins may delete users
				if self.usr_type != KONTO_ADMIN:
					self.send("ERROR:Access denied")
					return
				
				self.send("USR")
				
				# Get username
				username = self.recv_str()
				
				# Remove user
				self.db.remove_user(username)
				
				# Send confirmation
				self.send("PASS")
			
			elif cmd == "SYNC":
				
				# Get SyncData object
				sd = self.get_syncdata()
				
				# Send sync data
				self.send(sd.to_utf8())
	
	def logout(self):
		""" Logout the user. Deauthorize the client."""
		
		global user_directory, directory_mutex
		
		# Remove client from directory
		with directory_mutex:
			
			found_user = False
			
			# Verify that user exists in directory
			if self.auth_user not in user_directory:
				self.log.error("Logged-in user was not found in directory. Perhaps they were removed prematurely.")
			else:
				# Scan over all logged in clients for this user
				found_user = True
				for idx, de in enumerate(user_directory[self.auth_user]):
					
					# Check if this last_update_time matches this client. Any DirectoryEntry parameter would work though.
					if de.t is self.last_update_time:
						
						found_user = True
						
						# Remove user
						del user_directory[self.auth_user][idx]
						
						# Delete username key from directory if no instances from client remain
						if len(user_directory[self.auth_user]) == 0:
							del user_directory[self.auth_user]
						
			# Check for failure to find and remove user
			if not found_user:
				# If this runs, it could mean a garbage collection thread erased the client, OR that the code
				# accidentally modified the address of one of the ServerAgent's parameters (specifically last_update_time)
				# and now the system is broken!
				self.log.error("Failed to find user's client data address in directory. This could be a bug in server code.")
		
		# Empty any outstanding messages/notifications
		self.notes.clear()
		
		# Deauthorize client
		self.auth_user = None
		self.acct_id = None
		self.usr_type = None
		
		# Send message
		self.log.info(f"{self.id_str}Successfully logged-out user: {self.auth_user}")

	def prepare_exit(self):
		""" Marks the client object to close. This thread will close
		under normal conditions when the next loop runs. """
		
		# Sure this is super simple for now, but who knows if this process will
		# get more complex later.
		
		# Prepare to exit
		self.state = ServerAgent.TS_EXIT
	
	def create_message(self, user:str, msg:str):
		""" Sends a message to the specified client 'user'. """
		
		global distribution_mutex, distribution_inbox
		
		# Create message object
		new_msg = Message(self.auth_user, user, msg)
		
		# Add object to inbox
		with distribution_mutex:
			distribution_inbox.append(new_msg)
			
	def get_syncdata(self):
		""" Saves all data the client needs to a SyncData object and 
		returns it."""
		
		# Create object
		sd = SyncData()
		
		self_addr = hex(id(self.notes))
		self.debug(f"Number of messages to send: {len(self.notes)}. Self address: {self_addr}")
		
		# Populate notes
		sd.notes = copy.deepcopy(self.notes)
		
		# Populate sharedata
		if self.sharedata_mutex is None:
			sd.packed_sharedata = self.sharedata.pack()
		else:
			# Acquire sharedata mutex
			with self.sharedata_mutex:
				sd.packed_sharedata = self.sharedata.pack()
		
		self.notes.clear() # Clear local notes
		
		return sd
	
	#TODO: Way to automatically add thread-id string to pylogfile and replace these functions
	def debug(self, msg:str):
		""" Adds thread string to debug logging message """
		self.log.debug(f"{self.id_str}{msg}")
	
	def info(self, msg:str):
		""" Adds thread string to debug logging message """
		self.log.info(f"{self.id_str}{msg}")
	
	def warning(self, msg:str):
		""" Adds thread string to debug logging message """
		self.log.warning(f"{self.id_str}{msg}")
	
	def error(self, msg:str):
		""" Adds thread string to debug logging message """
		self.log.error(f"{self.id_str}{msg}")
	
	def critical(self, msg:str):
		""" Adds thread string to debug logging message """
		self.log.critical(f"{self.id_str}{msg}")
import socket
import threading
import msgpack

from colorama import Fore, Style, Back

from pylogfile.base import *

import rsa
import sys
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from dataclasses import dataclass
import time
from typing import Callable
from pyfrost.base import *

from PyQt6 import QtCore, QtWidgets
from PyQt6.QtWidgets import QWidget, QLabel, QGridLayout, QMainWindow

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

lobby_id_mutex = threading.Lock()
next_lobby_id = 0

lobby_master_lock = threading.Lock() # Lock to protect `lobby_objects` and `lobby_locks`
lobby_objects = [] # List of lobby objects. Each client will have a `self.lobby` that points to one of these, but must be accessed by it's `self.lobby_lock` which points to an item in the list `lobby_locks`
# Each Lobby object must:
# - Inherit from Serializable
# - Define a function: `client_count()` that returns number of clients using it. WHen
#	zero, the garbage collection thread will delete it.
# 

lobby_locks = [] # List of mutexes to protect each of the corresponding lobby objects.



# #TODO: sharedata might be redundant now that lobby_objects was added.
# # Master mutex protects the lists: 'sharedata_objects' and 'sharedata_mutexes'
# master_mutex = threading.Lock()
# sharedata_objects = [] # This will hold all the sharedata objects (This is a pool of data shared between mult clients and sync'd via the server.)
# sharedata_mutexes = [] # This will hold all the mutexes for each sharedata obejct

# Distribution mutex protects the distribution inbox
distribution_mutex = threading.Lock()
distribution_inbox = [] # List of incoming notifications for the distribution thread to pass to each user

# The directory mutex is used to lock the user directory
directory_mutex = threading.Lock()
user_directory = {} # This will hold tuples of user note lists and their mutexes

# Initialize database access
db_mutex = threading.Lock() # Create a mutex for the database

# Create server stat print timer variable
# This object is not protected by a mutex and should only ever be used by the stats thread

#TODO: Replace this
standard_color = Fore.WHITE

# Prepare logs
id_str = f"{Fore.LIGHTMAGENTA_EX}[T-ID: {Fore.WHITE}MAIN{Fore.LIGHTMAGENTA_EX}]{standard_color} "
log = LogPile()

log.info(f"{id_str}Server online")

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
	
	def __init__(self, sock, thread_id, log:LogPile, query_func:Callable[..., None]=None, send_func:Callable[..., None]=None, connection_state=None, lobby_pair:tuple=None, stowaway=None):
		'''
		lobby_pair is a tuple and expects a Serializable lobby object (in global/shared memory) as
			the first element, and a mutex (also in global/shared memeory) in the second index.
		
		'''
		super().__init__()
		
		# Log object
		self.log = log
		
		# Captures which screen/state the client should be in and what type of
		# commands server should be ready for
		self.state = ServerAgent.TS_HAND
		
		# Only firm requirement is that this object is a Serializable. However, in
		# the pyfrost network model, this object is intended to house a state
		# machine that tracks the state of the connection to the client. This way
		# the server knows how to behave in response to client commands.
		self.connection_state = connection_state
		
		# Must be Serializable. The lobby object is intended to point to an object in the global variable 
		# `lobby_objects`. A lobby is supposed to be an object shared between multiple
		# clients (which is presumably required in a networked application).
		if lobby_pair is not None:
			try:
				self.lobby_mtx = lobby_pair[0]
				self.lobby = lobby_pair[1]
			except Exception as e:
				self.log.critical(f"Invalid lobby argument passed. ({e})")
				raise ValueError
		else:
			self.lobby_mtx = None
			self.lobby = None
		
		# Must be Serializable. The stowaway is an additional object you can add to the ServerAgent outside
		# of the typical pyfrost connection model. This was originally used to
		# house the self.connection_state object before this became a formailzed
		# variable.
		self.stowaway = stowaway

		# Client user data
		self.auth_user = None # This will have username of user who has been authorized as loged in
		self.acct_id = None # CLient account ID
		self.usr_type = None # type of account
		
		# Controls if it enforces minimum password requirement rules.
		self.enforce_password_rules = True
		self.send_func = send_func # Returns None if command is not recognized, otherwise return True or False for execution success status.
		self.query_func = query_func # Return NOne if not recognized, otehrwise return a GenData object
		
		# Socket object from connecting to client program
		self.sock = sock
		
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
		
		# # These will point to a sharedata and mutex in the main 'sharedata' and 'sharedata_mutexes'
		# # lists. Use sharedata_mutex prior to modifying the sharedata object.
		# self.sharedata = ThreadSafeDict()
		# self.sharedata_mutex = None
		
		# The notes array contains any incoming notifications or messages. It will be modified
		# by the distribution thread, so be sure to always use the mutex before checking/modifying it.
		self.notes = []
		self.notes_mtx = threading.Lock()
		
		# This is a dictionary that the end-user application can modify. This way, using the initialization
		# function option provided in server_main(), data can be stored inside the SA object.
		self.app_data = {}
	
	def execute_sendgc(self, gc:GenCommand):
		''' Executes a generalized command. Returns true if executed without error.
		 
		NOTE: This function should NOT return any data to the client. It must simply 
		populate any error register (game.error_message) and return True or False.
		'''
		
		logging.debug(f"Executing GenCommand: [{gc.command}], data={gc.data}, meta={gc.metadata}")
		
		if gc.command == "MSGUSR":
			
			# Check fields present
			gch = gc.has(['RECIP', "MSG"])
			if gch < 0:
				logging.error("GenCommand missing required data fields.")
				return False
			elif gch > 1:
				logging.warning("GenCommand contains un-used data fields")
				
			# Validate message
			filt_msg = validate_message(gc.data['MSG'])
				
			# Create message and pass it along!
			self.create_message(gc.data['RECIP'], filt_msg)
			
		else:
			
			# See if command is recognized in user extension function
			if self.send_func is not None:
				found_cmd = self.send_func(self, gc)
			else:
				found_cmd = None
			
			# Command was not found
			if found_cmd is None:
				logging.warning(f"Failed to recognize generalized command: {gc.command}.")
				return False
			else:
				if found_cmd:
					logging.debug(f"Successfully executed generalized command: {gc.command}.")
				else:
					logging.warning(f"Failed to execute generalized command: {gc.command}.")
		
		return True
	
	def execute_querygc(self, gc:GenCommand):
		''' Executes a generalized command. Returns true if executed without error.
		 
		NOTE: This function DOES return data as a GenData object but it RETURNS it, it should NOT send data itself to the client. The whole point of the GenCommand/Data system is to avoid 
		having each command implement its own comm system. I want all of that handled by GenCommand
		and GenData automatically. If an error occurs, returns a GenData object with STATUS
		set to False and you can add text to the error variable. You can also	populate any error register (game.error_message)..
		'''
		
		# Initialize error GD
		err_gd = GenData({"STATUS": False})
		
		logging.debug(f"Executing GenCommand: [{gc.command}], data={gc.data}, meta={gc.metadata}")
		
		if gc.command == "NUMUSER":
			
			# Check fields present
			gch = gc.has([])
			if gch > 1:
				logging.warning("GenCommand contains un-used data fields")
			
			# Get number of users
			with directory_mutex:
				num_unique = len(user_directory)
			
			# Return response to client
			gdata = GenData({"NUMUSER":num_unique, "STATUS": True})
			return gdata
		
		else:
			
			# See if command is recognized in user extension function
			if self.query_func is not None:
				gdata = self.query_func(self, gc)
				return gdata
			else:
				logging.warning(f"Failed to recognize generalized command: {gc.command}.")
				err_gd.metadata['error_str'] = "Failed to recognize command."
				return err_gd
	
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
				if self.enforce_password_rules and (not self.check_valid_password(password)): # password Failed
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
			if cmd == "SENDGC":
				
				# Send ack
				self.send("ACK")
				
				# Receive command
				data_bytes = self.recv()
				gc = GenCommand()
				gc.from_utf8(data_bytes)
				
				# Execute command
				if self.execute_sendgc(gc):
					self.send("ACK")
				else:
					self.send(f"SERVFAIL:")
			
			if cmd == "QRYGC":
				
				# Send ack
				self.send("ACK")
				
				# Receive command
				data_bytes = self.recv()
				gc = GenCommand()
				gc.from_utf8(data_bytes)
				
				# Execute command
				gdata = self.execute_querygc(gc)
				
				# Return value from execute_querygc should be a GenData, however, here we check for None
				# because this function's return value can depend on the end user (who can provide extension
				# functions), so we check for None in case they forgot to return their GenData.
				if gdata is None:
					gdata = GenData({"STATUS": False})
					gdata.metadata['error_str'] = "execute_querygc returned None. This likely means the user's query_func returned None incorrectly!"
					
				# Send gdata on to client. Even if an error occured, this gdata will
				# contain the error message for the client to see.
				self.send(gdata.to_utf8())
				
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
				
				db_str = self.db.view_database()
				
				# Return database string
				self.send(db_str)
			
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
				sd_dict = to_serial_dict(sd)
				payload = msgpack.packb(sd_dict, use_bin_type=True) # Serialize dictionary
				self.send(payload, no_encode=True)
	
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
	
	def create_message(self, user:str, msg:str, sender:str=None):
		""" Sends a message to the specified client 'user'. """
		
		global distribution_mutex, distribution_inbox
		
		# Create message object
		if sender is None:
			new_msg = Message(self.auth_user, user, msg)
		else:
			new_msg = Message(sender, user, msg)
		
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
		
		if self.lobby_mtx is not None:
			with self.lobby_mtx:
				sd.lobby = copy.deepcopy(self.lobby) #TODO: Make sure this works
		else:
			sd.lobby = None
		sd.connection_state = self.connection_state
		sd.stowaway = self.stowaway
		
		if self.lobby_mtx is None:
			print(f"Lobby mutex is NONE")
		else:
			with self.lobby_mtx:
				print(f"Lobby: {sd.lobby}", flush=True)
		print(f"Connection-state: {sd.connection_state}")
		print(f"Stowaway: {sd.stowaway}")
		
		# # Populate sharedata
		# if self.sharedata_mutex is None:
		# 	sd.packed_sharedata = self.sharedata.pack()
		# else:
		# 	# Acquire sharedata mutex
		# 	with self.sharedata_mutex:
		# 		sd.packed_sharedata = self.sharedata.pack()
		
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
		
		# Encrypt data - produce primary data block
		primary_data_block = cipher.encrypt(pad(x, AES.block_size))
		
		# Create length of primary data block specifier block
		pdb_len = len(primary_data_block) # Get length of primary block
		pdb_len_bytes_needed = (pdb_len.bit_length() + 7) // 8 # Get how many bytes needed to represent that number
		pdb_len_block = pdb_len.to_bytes(pdb_len_bytes_needed, 'big', signed=False) # Convert to bytes
		
		# Create initial byte with length of primary block length specifier
		plb_len = len(pdb_len_block) # Get length of block (should be same as pdb_len_bytes_needed)
		init_byte = plb_len.to_bytes(1, 'big', signed=False) # Create initial byte
		
		# Try to send encrypted message
		try:
			self.sock.send(init_byte)
			self.sock.send(pdb_len_block)
			self.sock.send(primary_data_block)
		except socket.error as e:
			self.log.error(f"{self.id_str}Failed to send data to client. ({str(e)})")
			return False

		return True
		
	def recv(self):
		""" Receives and decrypts binary data from the client using AES encryption."""
		
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
			rv = unpad(cipher.decrypt(data_block), AES.block_size) #TODO: Make this work with messages bigger than a packet

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
		if self.usr_type != KONTO_ADMIN:
			new_usr_class = KONTO_STANDARD
		
		# Add to database
		return self.db.add_user(username, password, email, new_usr_class)

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

def garbage_collect_thread_main():
	""" This thread periodically checks for global resources on the server that are no longer
	used and can be deleted. """
	
	global server_opt
	global lobby_objects, lobby_locks, lobby_master_lock
	global user_directory, directory_mutex
	
	time_last_collect = time.time()
	
	garb_id_str = f"{Fore.LIGHTMAGENTA_EX}[T-ID: {Fore.WHITE}GARB{Fore.LIGHTMAGENTA_EX}]{standard_color} "
	
	while not server_opt.kill_garbage_thread:
		
		# Run garbage collection when time elapses
		if time.time() - time_last_collect > SERVER_STAT_PRINT:
			
			#TODO: Make pylogfile threadsafe and add these back in
			# logging.debug(f"{garb_id_str}Running garbage collection")
			
			# Get master mutex
			with lobby_master_lock:
				
				#TODO: I should probably create a list of users and IDs so
				# I can't find the correct game without using the global mutex.
				# Scan over all game objects, look for ID
				#TODO: Instead of matching their indecies, I should probably make them a touple or something
				for idx, go in enumerate(lobby_objects):
					
					delete_this_index = False
					
					# Get local mutex
					with lobby_locks[idx]:
						if go.client_count() == 0: # If game has no players, delete it
							delete_this_index = True
					if delete_this_index:
						# logging.info(f"{garb_id_str}Deleting game [Lobby ID={go.id}]")
						del lobby_locks[idx]
						del lobby_objects[idx]
			
			
			# # Get master mutex
			# with master_mutex:
			# 	
			# 	#TODO: I should probably create a list of users and IDs so
			# 	# I can't find the correct game without using the global mutex.
			# 	# Scan over all game objects, look for ID
			# 	#TODO: Instead of matching their indecies, I should probably make them a touple or something
			# 	for idx, go in enumerate(sharedata_objects):
			# 		
			# 		delete_this_index = False
			# 		
			# 		# Get local mutex
			# 		with sharedata_mutexes[idx]:
			# 			if len(go.client_count) == 0: # If game has no players, delete it
			# 				delete_this_index = True
			# 		if delete_this_index:
			# 			# logging.info(f"{garb_id_str}Deleting game [Lobby ID={go.id}]")
			# 			del sharedata_mutexes[idx]
			# 			del sharedata_objects[idx]
			
			time_last_collect = time.time()
		
		time.sleep(2)
	
	# logging.info(f"{garb_id_str}Garbage-collection thread shutting down")

def distribution_thread_main():
	""" This is the main function for the distribution thread. It's job
	 is to take messages in the distribution inbox and pass them along to their respective clients """
	
	global distribution_inbox, distribution_mutex
	global user_directory, directory_mutex
	
	dist_id_str = f"{Fore.LIGHTMAGENTA_EX}[T-ID: {Fore.WHITE}DIST{Fore.LIGHTMAGENTA_EX}]{standard_color} "
	
	# Main loop
	while not server_opt.kill_distribution_thread: #TODO: This should be mutex protected!
			
		# Acquire the inbox
		with distribution_mutex:
			
			# If messages are present, pass them along
			if len(distribution_inbox) > 0:
				
				t0 = time.time()
				
				# Acquire the directory
				with directory_mutex:
				
					#TODO: Perhaps you don't want to distribute *all* messages, in case that adds too much latency to new message additions
				
					# Distribute all messages to recipient
					num_deliv = 0
					while len(distribution_inbox) > 0:
						
						msg = distribution_inbox[0]
						
						# Check if user is logged in
						if msg.recipient in user_directory:
							
							#TODO: Find a way to abort after some time? What if a user hangs their mutex and distribution thread freezes forever?
							
							# Get user info
							de_list = user_directory[msg.recipient]
							
							# Scan over all logged-in clients (for specified user)
							for de in de_list:
								# logging.debug(f"{dist_id_str}Sending message to {msg.recipient}. Mutex:{de.note_mutex}, ListObj:{de.note_list}")
							
								# Acquire the user's note list mutex
								with de.note_mutex:
									de.note_list.append(msg) # Add message to their list
								
								num_deliv += 1
								
						else:
							#TODO: Eventually save to disk, and pass along later?
							#TODO: Eventually send message saying delivery failed (back to sender)
							
							logging.info(f"{dist_id_str}Deleting message - recipient not active")
							
						# Remove message
						del distribution_inbox[0]
				
				# logging.info(f"{dist_id_str}Distributed {num_deliv} messages ({round(1e5*(time.time()-t0))/1e2} ms)")
		
		# Pause - A little latency is fine, then this thread won't swamp one CPU core trying
		# to distribute the mail 1M times per second
		time.sleep(0.5)
	
	logging.info(f"{dist_id_str}Distribution thread shutting down")

def server_stat_thread_main(window=None):
	""" This is the main function for the stat thread. It's job is to 
	 periodically display status info about the server. """
	
	global server_opt
	global lobby_objects, lobby_master_lock
	global user_directory, directory_mutex
	
	time_last_print = time.time()
	
	stat_id_str = f"{Fore.LIGHTMAGENTA_EX}[T-ID: {Fore.WHITE}STAT{Fore.LIGHTMAGENTA_EX}]{standard_color} "
	
	while not server_opt.kill_stat_thread:
			
		if time.time() - time_last_print > SERVER_STAT_PRINT:
			
			# # Count number of games
			# with master_mutex:
			# 	num_sdo = len(sharedata_objects)
						# Count number of games
			with lobby_master_lock:
				num_sdo = len(lobby_objects)
			
			# Count number of logged-in users
			with directory_mutex:
				num_unique = len(user_directory)
			
				num_active = 0
				for usr_name in user_directory.keys():
					num_active += len(user_directory[usr_name])
			
			# logging.info(f"{stat_id_str}Active Threads: {threading.active_count()}")
			# logging.info(f"{stat_id_str}Kill server: {not server_opt.server_running}")
			print(f"{Fore.YELLOW}Server Stats:{Style.RESET_ALL}")
			print(f"\t{Fore.YELLOW}Active Threads: {Style.RESET_ALL}{threading.active_count()}")
			print(f"\t{Fore.YELLOW}Kill server: {Style.RESET_ALL}{not server_opt.server_running}")
			print(f"\t{Fore.YELLOW}Number of shared objects: {Style.RESET_ALL}{num_sdo}")
			print(f"\t{Fore.YELLOW}Active Logins: {Style.RESET_ALL}")
			print(f"\t{Fore.YELLOW}\tUsers: {Style.RESET_ALL}{num_unique}")
			print(f"\t{Fore.YELLOW}\tClient Conn.: {Style.RESET_ALL}{num_active}", flush=True)
			
			if window is not None:
				window.stats_widget.update_vals(threading.active_count(), num_sdo, num_unique, num_active)
			
			time_last_print = time.time()
		
		time.sleep(1)
	
	logging.info(f"{stat_id_str}Stat thread shutting down")

class StatsWidget(QWidget):
	
	def __init__(self):
		super().__init__()
		
		self.grid = QGridLayout()
		
		self.title_label = QLabel("Server Stats:")
		self.grid.addWidget(self.title_label, 0, 0, 1, 2)
		self.title_label.setAlignment(QtCore.Qt.AlignmentFlag.AlignHCenter)
		
		row = 1
		self.active_label = QLabel("Active Threads:")
		self.active_label_val = QLabel("--")
		self.grid.addWidget(self.active_label, row, 0)
		self.grid.addWidget(self.active_label_val, row, 1)
		
		row = 2
		self.sdo_label = QLabel("Shared Objects:")
		self.sdo_label_val = QLabel("--")
		self.grid.addWidget(self.sdo_label, row, 0)
		self.grid.addWidget(self.sdo_label_val, row, 1)
		
		row = 3
		self.actlogin_label = QLabel("Active Logins:")
		self.grid.addWidget(self.actlogin_label, row, 0, 1, 2)
		self.actlogin_label.setAlignment(QtCore.Qt.AlignmentFlag.AlignHCenter)
		
		row = 4
		self.users_label = QLabel("Logged-in Users:")
		self.users_label_val = QLabel("--")
		self.grid.addWidget(self.users_label, row, 0)
		self.grid.addWidget(self.users_label_val, row, 1)
		
		row = 5
		self.client_label = QLabel("Connected Clients:")
		self.client_label_val = QLabel("--")
		self.grid.addWidget(self.client_label, row, 0)
		self.grid.addWidget(self.client_label_val, row, 1)
		
		self.setLayout(self.grid)
	
	def update_vals(self, num_threads:int, num_sdo:int, num_users:int, num_clients:int):
		
		self.active_label_val.setText(f"{num_threads}")
		self.sdo_label_val.setText(f"{num_sdo}")
		self.users_label_val.setText(f"{num_users}")
		self.client_label_val.setText(f"{num_clients}")

class PyfrostServerGUI(QMainWindow):
	
	def __init__(self, log, app, gui_title:str, *args, **kwargs):
		super().__init__(*args, **kwargs)
		
		# Save local variables
		self.log = log
		
		self.setWindowTitle(gui_title)
		
		self.grid = QtWidgets.QGridLayout()
		
		self.stats_widget = StatsWidget()
		self.grid.addWidget(self.stats_widget, 0, 0)
		
		# Set the central widget
		central_widget = QtWidgets.QWidget()
		central_widget.setLayout(self.grid)
		self.setCentralWidget(central_widget)
		
		self.show()

def server_main(sock:socket, query_func:Callable[..., None]=None, send_func:Callable[..., None]=None, sa_init_func:Callable[..., None]=None, use_gui:bool=True, gui_title:str="Pyfrost Server Status", loglevel:str="WARNING", detail:bool=False, stowaway=None):
	'''
	
	stowaway: Optional class type that, if provided, will be created inside each serverAgent. This provides
		a easy way of passing objects to each thread, much like customizing the ServerAgent itself.
	
	'''
	
	if use_gui:
		
		log = LogPile()
		app = QtWidgets.QApplication(sys.argv)
		main_window = PyfrostServerGUI(log, app, gui_title)
		app.setStyle("Fusion")
		
		server_thread = threading.Thread(target=server_main_loop, args=(sock, query_func, send_func, sa_init_func, main_window, gui_title, loglevel, detail, stowaway))
		server_thread.daemon = True
		server_thread.start()
		
		app.exec()
	
	else:
		
		server_main_loop(sock, query_func, send_func, sa_init_func, loglevel=loglevel, detail=detail)

def server_main_loop(sock:socket, query_func:Callable[..., None]=None, send_func:Callable[..., None]=None, sa_init_func:Callable[..., None]=None, main_window=None, gui_title:str="Pyfrost Server Status", loglevel:str="WARNING", detail:bool=False, stowaway=None):
	''' Main loop that spawns new threads, each with a new ServerAgent, to handle incoming client
	connections. Socket is the socket new clients will connect to. Functions can be provided to add
	GenCOmmand handlers for the server, or to initialize the ServerAgents per the users needs (such as
	adding fields to the app_data dict).
	
	query_func: Signature (sa:ServerAgent, gc:GenCommand) -> Bool (or None if command not found)
		* Must return a bool for execution success status. Return None if command not recognized.
		* Handles all 'send' commands (ie. those without a GenData returned to the client).
	
	send_func: Signature (sa:ServerAgent, gc:GenCommand) -> GenData (or None if command not found)
		* Must return a GenData (with a status field). Set status field to false if execution
		  failed or encountered an error. Place any error messages in the 'metadata' dict, under
		  the key 'error_str'.
		* Handles all 'query' commands (ie. those which expect a GenData returned to the client).
	
	sa_init_func: Signature (sa:ServerAgent) -> ServerAgent
		* Modifies the provided ServerAgent and returns it. 
		* Can be used to initialize a ServerAgent per the users needs prior to being started in 
		  a new thread.
	
	stowaway: Optional class type that, if provided, will be created inside each serverAgent. This provides
		a easy way of passing objects to each thread, much like customizing the ServerAgent itself. Object must be initialized
		with no arguments. Use sa_init_func if you need to initialize it in some way.
	
	 '''
	
	global next_thread_id, server_opt
	
	# Create thread to print server stats periodically
	if main_window is not None:	# Start with GUI
		stats_thread = threading.Thread(target=server_stat_thread_main, args=(main_window,))
		stats_thread.start()
	else: # Start without GUI
		stats_thread = threading.Thread(target=server_stat_thread_main)
		stats_thread.start()
	
	# Create thread to deliver messages
	distribution_thread = threading.Thread(target=distribution_thread_main)
	distribution_thread.start()
	
	# Create thread to delete unused assets
	garbage_collect_thread = threading.Thread(target=garbage_collect_thread_main)
	garbage_collect_thread.start()
	
	# Loop accept client connections
	while server_opt.server_running:
		
		# Accept a new client connection
		try:
			client_socket, client_addr = sock.accept()
		except socket.timeout:
			logging.info(f"{id_str}Timed out waiting for client")
			continue
		
		
		logging.info(f"{id_str}Accepted client connected on address <{client_addr}>")
		
		# Create and configure log object
		new_log = LogPile()
		new_log.set_terminal_level(loglevel)
		new_log.str_format.show_detail = detail
		
		# Create state_object if provided
		if stowaway is not None:
			new_so = stowaway()
		else:
			new_so = None
		
		# Create server agent class
		sa = ServerAgent(client_socket, next_thread_id, new_log, query_func=query_func, send_func=send_func, stowaway=new_so)
		sa.enforce_password_rules = False # Allow weak passwords
		
		# Call initialization function if provided
		if sa_init_func is not None:
			sa = sa_init_func(sa)
		
		 # Update thread_id
		next_thread_id += 1
		
		# Start client thread
		sa.start()
	
	logging.info(f"{id_str}Server shutting down")
	server_opt.kill_stat_thread = True
	server_opt.kill_distribution_thread = True
	server_opt.kill_garbage_thread = True


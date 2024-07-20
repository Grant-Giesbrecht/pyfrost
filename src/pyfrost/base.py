import socket
import rsa
import tabulate
import threading
import hashlib
import sqlite3
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from pylogfile.base import *
from abc import ABC, abstractmethod
from jarnsaxa import *
import logging #TODO: Replace this with pylogfile eventually
import copy
import os
import datetime
import copy

LOG_LEVEL = logging.INFO
tabchar = "    "
prime_color = Fore.CYAN
standard_color = Fore.YELLOW
quiet_color = Fore.LIGHTBLACK_EX
# logging.basicConfig(stream=sys.stdout, format='%(asctime)s - %(message)s', level=logging.INFO)
logging.basicConfig(format=f'{prime_color}%(levelname)s:{standard_color} %(message)s{quiet_color} | %(asctime)s{Style.RESET_ALL}', level=LOG_LEVEL)

#TODO: Make it able to read over multiple packets
PACKET_SIZE = 16384
AES_KEY_SIZE = 32
SOCKET_TIMEOUT = 15 # Time (sec) between loop restarts if no new client
SERVER_STAT_PRINT = 5 # Time (sec) between server stat console print
GARBAGE_COLLECT_PERIOD = 2 # Time (sec) between server garbage collection cycles

ACCOUNT_ADMIN = 30
ACCOUNT_STANDARD = 20
ACCOUNT_LOW = 10

# Open help.json
help_data = {}
try:
	with open(os.path.join('Assets', 'help.json')) as f:
		help_data = json.load(f)
except Exception as e:
	print(f"Failed to read help.json: {e}")

# Initialize database access
db_mutex = threading.Lock() # Create a mutex for the database

def send_ptstring(sock, x, log:LogPile):
	""" Sends a plaintext string 'x' to the socket 'sock'
	"""
	
	try:
		sock.send(str.encode(x))
	except socket.error as e:
		log.error(f"Encountered an error while sending plain text string.", detail=f"{e}")

def get_ptstring(sock):
	""" Get plain text string """
	
	return sock.recv(PACKET_SIZE).decode()

def username_follows_rules(username:str):
	""" Checks if the string is a valid username. This does NOT check for
	if the username is already in use. """
	
	return re.match('^[a-zA-Z0-9_]+$',username)

def validate_message(message:str):
	""" Checks that the string only contains permitted characters. Any
	 unrecognized characters are replaced by question marks. """
	
	specials = ["!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "-", "+", "=", "\\", "|", "[", "]", ";", ":"]
	specials.extend(["\'", "\"", "?", "/", ".", ",", ">", "<", "`", "~", " ", "\t"])
	
	filt_msg = ""
	
	for c in message:
		
		# Permit if alphanumeric
		if c.isalnum():
			filt_msg = filt_msg + c
			continue
		
		# Check if permitted special character
		if c in specials:
			filt_msg = filt_msg + c
			continue
		
		# Change character
		filt_msg = filt_msg + '?'
	
	return filt_msg

def valid_email(email:str):
	""" https://www.zerobounce.net/python-email-verification/
	"""
	
	regex = r'^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w+$'
	return re.match(regex, email)
	

class UserDatabase:
	""" Handles interactions with, and manipulations of the user data database.
	
	It is supposed to abstract two things:
		1.) Hide database access from the coder using the 'db_mutex' variable
		2.) Hide SQL queries by burying them in functions
		3.) Hide database structure (in SQL queries) by burying it in functions.
		
	This way it's easy to restrucutre the database in the future if needed, and 
	there's no need to worry about database resource locks/races.
	"""
	
	def __init__(self, filename:str):
		
		# Name of database file
		self.filename = filename
		
	def remove_user(self, username:str):
		""" Deletes a user from the database """
		
		# Aquire mutex to protect database
		with db_mutex:
			
			conn = sqlite3.connect(self.filename)
			cur = conn.cursor()
			
			cur.execute("DELETE FROM userdata WHERE username = ?", (username,))
			
			conn.commit()
		
	def add_user(self, username:str, password:str, email:str, usr_type:str):
		""" Adds a user to the database. Returns true if successful """

		# Verify that user type is valid
		if usr_type not in [ACCOUNT_LOW, ACCOUNT_STANDARD, ACCOUNT_ADMIN]:
			usr_type = ACCOUNT_LOW
		
		# Get hash of password
		password_hash = hashlib.sha256(password.encode()).hexdigest()
		
		# Aquire mutex to protect database
		with db_mutex:
		
			conn = sqlite3.connect(self.filename)
			cur = conn.cursor()
						
			# Lookup highest account ID
			cur.execute("SELECT MAX(acct_id) FROM userdata")
			fd = cur.fetchall()
			try:
				next_ID = int(fd[0][0])+1
			except:
				self.log.critical(f"{self.id_str}Failed to access account ID from database.")
				return False
		
			cur.execute("INSERT INTO userdata (username, password, acct_id, email_addr, verified, acct_type, join_date) VALUES (?, ?, ?, ?, ?, ?, ?)", (username, password_hash, next_ID , email, "No", usr_type, str(datetime.datetime.now())))
			conn.commit()
		
		return True
	
	def get_user_id(self, username:str):
		""" Accepts a username and looks up the ID of that user. Returns None if 
		user is not found in the database."""
		
		# Aquire mutex to protect database
		with db_mutex:
			
			conn = sqlite3.connect(self.filename)
			cur = conn.cursor()
			
			# Check for user
			cur.execute("SELECT acct_id FROM userdata WHERE username = ?", (username,))
			qd = cur.fetchall()
			if qd:
				return qd[0][0]
			else:
				return None
	
	def get_user_type(self, username:str):
		""" Accepts a username and looks up the account type of that user. Returns None if
		user is not found in the database."""
		
		# Aquire mutex to protect database
		with db_mutex:
			
			conn = sqlite3.connect(self.filename)
			cur = conn.cursor()
			
			# Check for user
			cur.execute("SELECT acct_type FROM userdata WHERE username = ?", (username,))
			qd = cur.fetchall()
			if qd:
				return qd[0][0]
			else:
				return None

	def view_database(self):
		""" Access the entire database contents and return a table string"""
		
		# Hardcode - do not show password
		show_password = False
		
		# Query data from database
		with db_mutex:
			conn = sqlite3.connect(self.filename)
			cur = conn.cursor()
			
			cur.execute("SELECT * FROM userdata")
			
			# Get names
			names = list(map(lambda x: x[0], cur.description))
			
			# If told to hide password, deletes entry from names
			del_idx = None
			if not show_password:
				
				# Find password entry
				for idx, n in enumerate(names):
					if n == "password":
						del_idx = idx
				
				# Delete password item
				if del_idx is not None:
					del names[del_idx]
			
			# Get data
			cd = cur.fetchall()
		
		# Initialize master list
		table_data = []
		table_data.append(names)
		
		# Add user entries, one by one
		for entry in cd:
			
			# Create list
			entry_list = []
					
			# Scan over items in user entry
			for idx, e_item in enumerate(entry):
				
				# Skip passwords
				if idx == del_idx:
					continue
				
				entry_list.append(e_item)
		
			# Add to master lis
			table_data.append(entry_list)

		# Create table	
		T = tabulate.tabulate(table_data, headers='firstrow', tablefmt='fancy_grid')
		
		return str(T)

class Packable(ABC):
	""" This class represents all objects that can be packed and unpacked and sent between the client and server
	
	manifest, obj_manifest, and list_template are all dictionaries. Each describes a portion of how to represent a class as a string,
	and how to convert back to the class from the string data.
	
	manifest: lists all variables that can be converted to/from JSON natively
	obj_manifest: lists all variables that are Packable objects or lists of packable objects. Each object will have
		pack() called, and be understood through its unpack() function.
	list_template: dictionary mapping item to pack/unpack to its class type, that way during unpack, Packable knows which
		class to create and call unpack() on.
	
	Populate all three of these variables as needed in the set_manifest function. set_manifest is called in super().__init__(), so
	it shouldn't need to be remembered in any of the child classes.
	"""
	
	def __init__(self):
		self.manifest = []
		self.obj_manifest = []
		self.list_manifest = {}
		
		self.set_manifest()
	
	@abstractmethod
	def set_manifest(self):
		""" This function will populate the manifest and obj_manifest objects"""
		pass
	
	def pack(self):
		""" Returns the object to as a JSON dictionary """
		
		# Initialize dictionary
		d = {}
		
		# Add items in manifest to packaged data
		for mi in self.manifest:
			d[mi] = getattr(self, mi)
		
		# Scan over object manifest
		for mi in self.obj_manifest:
			# Pack object and add to output data
			d[mi] = getattr(self, mi).pack()
		
		# Scan over list manifest
		for mi in self.list_manifest:
				
			# Pack objects in list and add to output data
			d[mi] = [x.pack() for x in getattr(self, mi)]
				
		# Return data list
		return d
	
	def unpack(self, data:dict):
		""" Populates the object from a JSON dict """
		
		# Try to populate each item in manifest
		for mi in self.manifest:
			# Try to assign the new value
			try:
				setattr(self, mi, data[mi])
			except Exception as e:
				logging.error(f"Failed to unpack item in object of type '{type(self).__name__}'. ({e})")
				return
		
		# Try to populate each Packable object in manifest
		for mi in self.obj_manifest:
			# Try to update the object by unpacking the item
			try:
				getattr(self, mi).unpack(data[mi])
			except Exception as e:
				logging.error(f"Failed to unpack Packable in object of type '{type(self).__name__}'. ({e})")
				return
			
		# Try to populate each list of Packable objects in manifest
		for mi in self.list_manifest:
				
			# Scan over list, unpacking each element
			temp_list = []
			for list_item in data[mi]:
				# Try to create a new object and unpack a list element
				try:
					# Create a new object of the correct type
					new_obj = copy.deepcopy(self.list_manifest[mi])
					
					# Populate the new object by unpacking it, add to list
					new_obj.unpack(list_item)
					temp_list.append(new_obj)
				except Exception as e:
					logging.error(f"Failed to unpack list of Packables in object of type '{type(self).__name__}'. ({e})")
					return
			setattr(self, mi, temp_list)
				# self.obj_manifest[mi] = copy.deepcopy(temp_list)

class ThreadSafeData():
	''' Tracks a series of parameters, each of which is a list of any data type. Performs this
	management in a thread-safe manner. '''
	
	def __init__(self):
		super().__init__()
		
		# Data list. It should not be directly accessed because it needs to be modified and read only via mutex control
		self._data = {}
		self.mtx = threading.Lock()
	
	def add_param(self, param_name:str) -> bool:
		''' Adds a list under the parameter 'param_name'. '''
		
		with self.mtx: # Acquire mutex
			
			# Check if param already exists
			if param_name in self._data:
				# self.log.warning(f"Parameter '{param_name}' already exists in ThreadSafeData object.")
				return False
			
			# Initialize parameter
			self._data['param_name'] = []
	
	def append(self, param_name:str, val):
		''' Adds an element to the specified list. '''
		
		with self.mtx: # Acquire mutex
			
			# Check param exists
			if param_name not in self._data:
				# self.log.warning(f"Parameter '{param_name}' missing in ThreadSafeData object.")
				return False
			
			# Add value to list
			try:
				self._data[param_name].append(val)
			except Exception as e:
				# self.log.warning(f"Failed to add value to ThreadSafeData object.", detail=f"{e}")
				return False
		
		return True
	
	def read(self, param_name:str, idx:int):
		''' Reads the value of the specified parameter at the specified index. Returns a deepcopy of
		 the object so the return value is entirely thread safe. Returns none on error. '''
		
		with self.mtx: # Acquire mutex
			
			# Check param exists
			if param_name not in self._data:
				# self.log.warning(f"Parameter '{param_name}' missing in ThreadSafeData object.")
				return None
			
			# Check index in range
			if idx >= len(self._data[param_name]):
				# self.log.warning(f"Index out of bounds.")
				return None
			
			# REturn copy of value
			try:
				return copy.deepcopy(self._data[param_name][idx])
			except Exception as e:
				# self.log.warning(f"Failed to add value to ThreadSafeData object.", detail=f"{e}")
				return None
	
	def read_attr(self, param_name:str, idx:int, attr:str):
		''' Reads the value of the specified attribute of the specified parameter at the specified index. Returns
		 a deepcopy of the object so the return value is entirely thread safe. Returns none on error. '''
		
		with self.mtx: # Acquire mutex
			
			# Check param exists
			if param_name not in self._data:
				# self.log.warning(f"Parameter '{param_name}' missing in ThreadSafeData object.")
				return None
			
			# Check index in range
			if idx >= len(self._data[param_name]):
				# self.log.warning(f"Index out of bounds.")
				return None
			
			# Check attribute exists
			if attr not in self._data[param_name][idx].__dict__:
				# self.log.warning(f"Missing attribute.")
				return None
			
			# REturn copy of value
			try:
				return copy.deepcopy(self._data[param_name][idx].__dict__[attr])
			except Exception as e:
				# self.log.warning(f"Failed to add value to ThreadSafeData object.", detail=f"{e}")
				return None
	
	def set(self, param_name:str, idx:int, val):
		''' Sets a value of the specified parameter at the specified index. '''
		
		with self.mtx: # Acquire mutex
			
			# Check param exists
			if param_name not in self._data:
				# self.log.warning(f"Parameter '{param_name}' missing in ThreadSafeData object.")
				return False
			
			# Check index in range
			if idx >= len(self._data[param_name]):
				# self.log.warning(f"Index out of bounds.")
				return False
			
			# REturn copy of value
			try:
				self._data[param_name][idx] = val
			except Exception as e:
				# self.log.warning(f"Failed to add value to ThreadSafeData object.", detail=f"{e}")
				return False
		
		return True
	
	def set_attr(self, param_name:str, idx:int, attr:str, val):
		''' Sets a value of the specified parameter and attribute at the specified index. '''
		
		with self.mtx: # Acquire mutex
			
			# Check param exists
			if param_name not in self._data:
				# self.log.warning(f"Parameter '{param_name}' missing in ThreadSafeData object.")
				return False
			
			# Check index in range
			if idx >= len(self._data[param_name]):
				# self.log.warning(f"Index out of bounds.")
				return False
			
			# Check attribute exists
			if attr not in self._data[param_name][idx].__dict__:
				# self.log.warning(f"Missing attribute.")
				return False
			
			# Return copy of value
			try:
				self._data[param_name][idx].__dict__[attr] = val
			except Exception as e:
				# self.log.warning(f"Failed to add value to ThreadSafeData object.", detail=f"{e}")
				return False
		
		return True
	
	def remove(self, param_name:str, idx:int) -> bool:
		''' Deletes the value from the specified index. '''
		
		with self.mtx: # Acquire mutex
			
			# Check param exists
			if param_name not in self._data:
				# self.log.warning(f"Parameter '{param_name}' missing in ThreadSafeData object.")
				return False
			
			# Check index in range
			if idx >= len(self._data[param_name]):
				# self.log.warning(f"Index out of bounds.")
				return False
			
			# Return copy of value
			try:
				del self._data[param_name][idx]
			except Exception as e:
				# self.log.warning(f"Failed to add value to ThreadSafeData object.", detail=f"{e}")
				return False
		
		return True
	
	def find(self, param_name:str, val, end_on_find:bool=True) -> list:
		''' Checks each index of the specified parameter and looks for the provided value. Returns a
		a list of every index that matches. Returns only the first index if end_on_find is set to true.
		Returns an empty list if no matches occur.'''
		
		match_vals = []
		
		with self.mtx: # Acquire mutex
			
			# Check param exists
			if param_name not in self._data:
				# self.log.warning(f"Parameter '{param_name}' missing in ThreadSafeData object.")
				return match_vals
			
			# Scan over all values
			for idx, parval in enumerate(self._data[param_name]):
				
				# Check for match
				if parval == val:
					match_vals.append(idx)
					if end_on_find:
						break
		
		return match_vals
	
	def find_attr(self, param_name:str, attr:str, val, end_on_find:bool=True) -> list:
		''' Checks each index of the specified parameter and looks for the specified attribute
		to match the provided value.  Returns a	a list of every index that matches. Returns 
		only the first index if end_on_find is set to true.	Returns an empty list if no matches occur.'''
		
		match_vals = []
		
		with self.mtx: # Acquire mutex
			
			# Check param exists
			if param_name not in self._data:
				# self.log.warning(f"Parameter '{param_name}' missing in ThreadSafeData object.")
				return []
			
			# Scan over all values
			for idx, parval in enumerate(self._data[param_name]):
				
				# Check attribute exists
				if attr not in parval.__dict__:
					# self.log.warning(f"Missing attribute.")
					return []
				
				# Check for match
				if parval.__dict__[attr] == val:
					match_vals.append(idx)
					if end_on_find:
						break
		
		return match_vals

class GenData(Packable):
	''' Represents a packet of data sent between server and client. A GenData object is typically a response from the listener to the initiator, unless packaged into a more sophisticated child-class. '''
	
	def __init__(self, data={}):
		super().__init__()
		
		# Accompanying data
		self.data = data
		
		# Metadata
		self.metadata = {"created":str(datetime.datetime.now()), "error_str": ""}
	
	def has(self, key_list:list):
		''' Verifies that the command has the following data fields.
		
		returns -1 if one or more keys are missing
		returns  1 if all keys are present, no extras.
		returns  2 if all keys are present, and extras exist.
		
		'''
		
		# Get data key list
		dkl = self.data.keys()
		
		# Scan over each provided key
		for k in key_list:
			if k not in dkl:
				print(f"Missing {k}")
				return -1
		
		# Return 1 for exact match
		if len(dkl) == len(key_list):
			return 1
		
		# Return 2 if extra keys present
		return 2
	
	def auto_format(self):
		''' Only used in child class'''
		pass
	
	def set_manifest(self):
		
		self.manifest.append("data")
		self.manifest.append("metadata")
	
	def to_utf8(self):
		""" Saves the object's data to an encoded JSON string """
		
		# Make sure command is properly formatted
		self.auto_format()
		
		JD = self.pack()
		return json.dumps(JD).encode('utf-8')
	
	def from_utf8(self, json_data:bytes):
		""" Accepts JSON data (as bytes) and populates the object from the JSON data """
		
		# Get dictionary
		JD = json.loads(json_data.decode('utf-8'))
		self.unpack(JD)

	def validate_reply(self, key_list:list, log:LogPile, enforce_status:bool=False):
		''' Performs some validation on GenData objects used as a reply. 
		If you forget to check for STATUS it will automatically add it to the 
		cehck list unless you set enforce_status to false.'''
		
		if enforce_status and ('STATUS' not in key_list):
			key_list.append('STATUS')
		
		# Validate returned data
		gdh = self.has(key_list)
		if gdh < 0:
			log.error("GenData missing fields!")
			return False
		elif gdh > 1:
			log.warning("GenData contained unused fields.")
		
		# Check status (if enforced)
		if enforce_status and not self.data['STATUS']:
			es = self.metadata['error_str']
			log.error(f"GenData returned with ERROR status - ({es}).")
			return False
		
		return True
	
class GenCommand(GenData):
	''' Represents a command sent from initiator to listener. This can be packed as a JSON and
	replaces the older system of sending individual words back and forth from client to
	server. Typically GenCommand is sent from a client to the server, however if a network is configured to have clients listening for commands from the server 
	the server could send GenCommands to the client instead.
	'''
	
	def __init__(self, cmd:str="", data={}):
		super().__init__(data)
		
		# Save command
		self.command = cmd
	
	def set_manifest(self):
		super().set_manifest()
		
		self.manifest.append("command")
		
	def auto_format(self):
		''' Auto-formats command '''
		self.command = self.command.upper()

class Message(Packable):
	""" Object saved to distribution inbox to be passed along to other clients."""
	
	def __init__(self, sender:str=None, recip:str=None, msg:str=None):
		
		super().__init__()
		
		self.sender = sender
		self.recipient = recip
		self.msg = msg
	
		self.timestamp_created = str(datetime.datetime.now()) # Time when the message was received by the server
		
		# self.set_manifest()
		
	def set_manifest(self):
		
		self.manifest.append("sender")
		self.manifest.append("msg")
		self.manifest.append("recipient")
		self.manifest.append("timestamp_created")

class SyncData(Packable):
	""" TODO: UPDATE
	"""
	
	def __init__(self):
		
		super().__init__()
		
		#TODO: UPDATE This
		#=======================================================================#
		#                    HOW TO ADD FIELDS TO SyncData                      #
		# 1. Add to __init__() function											#
		# 2. Add to to_utf8() and from_utf8()									#
		# 3. In ServerAgent: (server_core.py)									#
		#	   I. Add field to get_syncdata() 									#
		# 4. In ClientAgent: (core.py)											#
		#      II. Add field to sync()											#
		#																		#
		#=======================================================================#
		# TO PACK OR NOT TO PACK?												#
		#	* As long as it's consistent for any one variable, it doesn't 		#
		#	  matter much. For some objects packing sooner is easier as it		#
		#	  makes it easier to not mess up the mutex/addressing.				#
		#																		#
		#=======================================================================#
		
		self.notes = [] # Notifications/messages for the user in unpacked form
		
		self.packed_sharedata = {} # ThreadSafeData object for client in PACKED form
		
		# ---1. Finish writing this class
		# ---2. Give it a better name?
		# 3. On the server side, make the ServerAgent create a SyncState object
		# 4. server passes serialized (via JSON: https://stackoverflow.com/questions/23876608/how-to-send-the-content-of-a-dictionary-properly-over-sockets-in-python3x)
		#    SyncState object to client
		# 5. Client unpacks SyncState object, updates itself
		# 6. CLI (or GUI later), having just called sync, knows to look for cool new shits and display stuff
		
		# self.set_manifest()
	
	def set_manifest(self):
		
		self.manifest.append("packed_sharedata")
		
		self.list_manifest['notes'] = Message()
	
	def to_utf8(self):
		""" Saves the object's data to an encoded JSON string """
		
		JD = self.pack()
		return json.dumps(JD).encode('utf-8')
	
	def from_utf8(self, json_data:bytes):
		""" Accepts JSON data (as bytes) and populates the object from the JSON data """
		
		# Get dictionary
		JD = json.loads(json_data.decode('utf-8'))
		self.unpack(JD)	


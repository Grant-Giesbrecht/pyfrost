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

# Create server stat print timer variable
# This object is not protected by a mutex and should only ever be used by the stats thread

#TODO: Replace this
standard_color = Fore.WHITE

# Prepare logs
id_str = f"{Fore.LIGHTMAGENTA_EX}[T-ID: {Fore.WHITE}MAIN{Fore.LIGHTMAGENTA_EX}]{standard_color} "
log = LogPile()

log.info(f"{id_str}Server online")

def garbage_collect_thread_main():
	""" This thread periodically checks for global resources on the server that are no longer
	used and can be deleted. """
	
	global server_opt
	global sharedata_objects, master_mutex
	global user_directory, directory_mutex
	
	time_last_collect = time.time()
	
	garb_id_str = f"{Fore.LIGHTMAGENTA_EX}[T-ID: {Fore.WHITE}GARB{Fore.LIGHTMAGENTA_EX}]{standard_color} "
	
	while not server_opt.kill_garbage_thread:
		
		# Run garbage collection when time elapses
		if time.time() - time_last_collect > SERVER_STAT_PRINT:
			
			#TODO: Make pylogfile threadsafe and add these back in
			# logging.debug(f"{garb_id_str}Running garbage collection")
			
			# Get master mutex
			with master_mutex:
				
				#TODO: I should probably create a list of users and IDs so
				# I can't find the correct game without using the global mutex.
				# Scan over all game objects, look for ID
				#TODO: Instead of matching their indecies, I should probably make them a touple or something
				for idx, go in enumerate(sharedata_objects):
					
					delete_this_index = False
					
					# Get local mutex
					with sharedata_mutexes[idx]:
						if len(go.client_count) == 0: # If game has no players, delete it
							delete_this_index = True
					if delete_this_index:
						# logging.info(f"{garb_id_str}Deleting game [Lobby ID={go.id}]")
						del sharedata_mutexes[idx]
						del sharedata_objects[idx]
			
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
	while not server_opt.kill_distribution_thread:
			
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
							
							# Scan over all logged-in clients
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

def server_stat_thread_main():
	""" This is the main function for the stat thread. It's job is to 
	 periodically display status info about the server. """
	
	global server_opt
	global sharedata_objects, master_mutex
	global user_directory, directory_mutex
	
	time_last_print = time.time()
	
	stat_id_str = f"{Fore.LIGHTMAGENTA_EX}[T-ID: {Fore.WHITE}STAT{Fore.LIGHTMAGENTA_EX}]{standard_color} "
	
	while not server_opt.kill_stat_thread:
			
		if time.time() - time_last_print > SERVER_STAT_PRINT:
			
			# Count number of games
			with master_mutex:
				num_games = len(sharedata_objects)
			
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
			print(f"\t{Fore.YELLOW}Number of games: {Style.RESET_ALL}{num_games}")
			print(f"\t{Fore.YELLOW}Active Logins: {Style.RESET_ALL}")
			print(f"\t{Fore.YELLOW}\tUsers: {Style.RESET_ALL}{num_unique}")
			print(f"\t{Fore.YELLOW}\tClient Conn.: {Style.RESET_ALL}{num_active}")
			
			
			time_last_print = time.time()
		
		time.sleep(1)
	
	logging.info(f"{stat_id_str}Stat thread shutting down")

def main():
	global next_thread_id, sock, server_opt
	
	# Create thread to print server stats periodically
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
		
		new_log = LogPile()
		
		# Accept a new client connection
		try:
			client_socket, client_addr = sock.accept()
		except socket.timeout:
			logging.info(f"{id_str}Timed out waiting for client")
			continue
		logging.info(f"{id_str}Accepted client connected on address <{client_addr}>")
		
		# Create server agent class
		sa = ServerAgent(client_socket, next_thread_id, new_log)
		sa.enforce_password_rules = False # Allow weak passwords
		
		 # Update thread_id
		next_thread_id += 1
		
		# Start client thread
		sa.start()
	
	logging.info(f"{id_str}Server shutting down")
	server_opt.kill_stat_thread = True
	server_opt.kill_distribution_thread = True
	server_opt.kill_garbage_thread = True

if __name__ == "__main__":
	
	main()
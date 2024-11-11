''' Minimum example for setting up a server using Pyfrost but with a GUI.
'''

from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtGui import QAction, QActionGroup, QDoubleValidator, QIcon, QFontDatabase, QFont, QPixmap
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtWidgets import QWidget, QTabWidget, QLabel, QGridLayout, QLineEdit, QCheckBox, QSpacerItem, QSizePolicy, QMainWindow, QSlider, QPushButton, QGroupBox, QListWidget, QFileDialog, QProgressBar, QStatusBar

from pyfrost.pf_server import *
import time
from pylogfile.base import *
import logging
import argparse
import sys

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
	
	# server_thread = threading.Thread(target=server_main, args=(sock, custom_func))
	# server_thread.daemon = True
	# server_thread.start()
	
	# launch_server_gui()

# class StatsWidget(QWidget):
	
# 	def __init__(self):
# 		super().__init__()
		
# 		self.grid = QGridLayout()
		
# 		self.title_label = QLabel("Server Stats:")
# 		self.grid.addWidget(self.title_label, 0, 0, 1, 2)
# 		self.title_label.setAlignment(QtCore.Qt.AlignmentFlag.AlignHCenter)
		
# 		row = 1
# 		self.active_label = QLabel("Active Threads:")
# 		self.active_label_val = QLabel("--")
# 		self.grid.addWidget(self.active_label, row, 0)
# 		self.grid.addWidget(self.active_label_val, row, 1)
		
# 		row = 2
# 		self.sdo_label = QLabel("Shared Objects:")
# 		self.sdo_label_val = QLabel("--")
# 		self.grid.addWidget(self.sdo_label, row, 0)
# 		self.grid.addWidget(self.sdo_label_val, row, 1)
		
# 		row = 3
# 		self.actlogin_label = QLabel("Active Logins:")
# 		self.grid.addWidget(self.actlogin_label, row, 0, 1, 2)
# 		self.actlogin_label.setAlignment(QtCore.Qt.AlignmentFlag.AlignHCenter)
		
# 		row = 4
# 		self.users_label = QLabel("Logged-in Users:")
# 		self.users_label_val = QLabel("--")
# 		self.grid.addWidget(self.users_label, row, 0)
# 		self.grid.addWidget(self.users_label_val, row, 1)
		
# 		row = 5
# 		self.client_label = QLabel("Connected Clients:")
# 		self.client_label_val = QLabel("--")
# 		self.grid.addWidget(self.client_label, row, 0)
# 		self.grid.addWidget(self.client_label_val, row, 1)
		
# 		self.setLayout(self.grid)
	
# 	def update_vals(self, num_threads:int, num_sdo:int, num_users:int, num_clients:int):
		
# 		self.active_label_val.setText(f"{num_threads}")
# 		self.sdo_label_val.setText(f"{num_sdo}")
# 		self.users_label_val.setText(f"{num_users}")
# 		self.client_label_val.setText(f"{num_clients}")

# class PyfrostServerGUI(QMainWindow):

# 	def __init__(self, log, app, *args, **kwargs):
# 		super().__init__(*args, **kwargs)
		
# 		# Save local variables
# 		self.log = log
		
# 		self.setWindowTitle("Pyfrost Server")
		
# 		self.grid = QtWidgets.QGridLayout()
		
# 		self.stats_widget = StatsWidget()
# 		self.grid.addWidget(self.stats_widget, 0, 0)
		
# 		# Set the central widget
# 		central_widget = QtWidgets.QWidget()
# 		central_widget.setLayout(self.grid)
# 		self.setCentralWidget(central_widget)
		
# 		self.show()

# log = LogPile()
# app = QtWidgets.QApplication(sys.argv)
# main_window = PyfrostServerGUI(log, app)
# app.setStyle("Fusion")

# def launch_server_gui():
# 	app.exec()

# def server_stat_thread_main_gui(window):
# 	""" This is the main function for the stat thread. It's job is to 
# 	 periodically display status info about the server. """
	
# 	global server_opt
# 	global sharedata_objects, master_mutex
# 	global user_directory, directory_mutex
# 	global main_window
	
# 	time_last_print = time.time()
	
# 	stat_id_str = f"{Fore.LIGHTMAGENTA_EX}[T-ID: {Fore.WHITE}STAT{Fore.LIGHTMAGENTA_EX}]{standard_color} "
	
# 	while not server_opt.kill_stat_thread:
			
# 		if time.time() - time_last_print > SERVER_STAT_PRINT:
			
# 			# Count number of games
# 			with master_mutex:
# 				num_sdo = len(sharedata_objects)
			
# 			# Count number of logged-in users
# 			with directory_mutex:
# 				num_unique = len(user_directory)
			
# 				num_active = 0
# 				for usr_name in user_directory.keys():
# 					num_active += len(user_directory[usr_name])
			
# 			# logging.info(f"{stat_id_str}Active Threads: {threading.active_count()}")
# 			# logging.info(f"{stat_id_str}Kill server: {not server_opt.server_running}")
# 			print(f"{Fore.YELLOW}Server Stats:{Style.RESET_ALL}")
# 			print(f"\t{Fore.YELLOW}Active Threads: {Style.RESET_ALL}{threading.active_count()}")
# 			print(f"\t{Fore.YELLOW}Kill server: {Style.RESET_ALL}{not server_opt.server_running}")
# 			print(f"\t{Fore.YELLOW}Number of shared objects: {Style.RESET_ALL}{num_sdo}")
# 			print(f"\t{Fore.YELLOW}Active Logins: {Style.RESET_ALL}")
# 			print(f"\t{Fore.YELLOW}\tUsers: {Style.RESET_ALL}{num_unique}")
# 			print(f"\t{Fore.YELLOW}\tClient Conn.: {Style.RESET_ALL}{num_active}", flush=True)
			
# 			window.stats_widget.update_vals(threading.active_count(), num_sdo, num_unique, num_active)
			
# 			time_last_print = time.time()
		
# 		time.sleep(1)
	
# 	logging.info(f"{stat_id_str}Stat thread shutting down")

# def server_main_gui(sock:socket, query_func:Callable[..., None]=None, send_func:Callable[..., None]=None, sa_init_func:Callable[..., None]=None, use_gui:bool=True, gui_title:str="Pyfrost Server Status"):
# 	''' Main loop that spawns new threads, each with a new ServerAgent, to handle incoming client
# 	connections. Socket is the socket new clients will connect to. Functions can be provided to add
# 	GenCOmmand handlers for the server, or to initialize the ServerAgents per the users needs (such as
# 	adding fields to the app_data dict).
	
# 	query_func: Signature (sa:ServerAgent, gc:GenCommand) -> Bool (or None if command not found)
# 		* Must return a bool for execution success status. Return None if command not recognized.
# 		* Handles all 'send' commands (ie. those without a GenData returned to the client).
	
# 	send_func: Signature (sa:ServerAgent, gc:GenCommand) -> GenData (or None if command not found)
# 		* Must return a GenData (with a status field). Set status field to false if execution
# 		  failed or encountered an error. Place any error messages in the 'metadata' dict, under
# 		  the key 'error_str'.
# 		* Handles all 'query' commands (ie. those which expect a GenData returned to the client).
	
# 	sa_init_func: Signature (sa:ServerAgent) -> ServerAgent
# 		* Modifies the provided ServerAgent and returns it. 
# 		* Can be used to initialize a ServerAgent per the users needs prior to being started in 
# 		  a new thread.
# 	 '''
	
# 	global next_thread_id, server_opt	
	
# 	# Create thread to print server stats periodically
# 	stats_thread = threading.Thread(target=server_stat_thread_main_gui, args=(main_window,))
# 	stats_thread.start()
	
# 	# Create thread to deliver messages
# 	distribution_thread = threading.Thread(target=distribution_thread_main)
# 	distribution_thread.start()
	
# 	# Create thread to delete unused assets
# 	garbage_collect_thread = threading.Thread(target=garbage_collect_thread_main)
# 	garbage_collect_thread.start()
	
# 	# Loop accept client connections
# 	while server_opt.server_running:
		
# 		new_log = LogPile()
		
# 		# Accept a new client connection
# 		try:
# 			client_socket, client_addr = sock.accept()
# 		except socket.timeout:
# 			logging.info(f"{id_str}Timed out waiting for client")
# 			continue
# 		logging.info(f"{id_str}Accepted client connected on address <{client_addr}>")
		
# 		# Create server agent class
# 		sa = ServerAgent(client_socket, next_thread_id, new_log, query_func=query_func, send_func=send_func)
# 		sa.enforce_password_rules = False # Allow weak passwords
		
# 		# Call initialization function if provided
# 		if sa_init_func is not None:
# 			sa = sa_init_func(sa)
		
# 		 # Update thread_id
# 		next_thread_id += 1
		
# 		# Start client thread
# 		sa.start()
	
# 	logging.info(f"{id_str}Server shutting down")
# 	server_opt.kill_stat_thread = True
# 	server_opt.kill_distribution_thread = True
# 	server_opt.kill_garbage_thread = True



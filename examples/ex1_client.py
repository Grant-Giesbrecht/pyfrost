from pyfrost.pf_client import *
from colorama import Fore, Style
import os

if os.name != 'nt':
	import readline

def autosync(ca:ClientAgent):
	
	# Sync client with server
	ca.sync()
	
	# Print messages if present
	if len(ca.notes) > 0:
		print(f"Messages:")
	for note in ca.notes:
		print(f"\t{Fore.LIGHTBLACK_EX}({note.timestamp_created}){Fore.YELLOW}[FROM: {note.sender}]{Style.RESET_ALL}{note.msg}")
	ca.notes = []

def barstr(text:str, width:int=80, bc:str='*', pad:bool=True):

		s = text;

		# Pad input if requested
		if pad:
			s = " " + s + " ";

		pad_back = False;
		while len(s) < width:
			if pad_back:
				s = s + bc
			else:
				s = bc + s
			pad_back = not pad_back

		return s

def print_help():
	
	help_color = Fore.WHITE
	help_bold = Fore.LIGHTMAGENTA_EX
	help_sudo = Fore.CYAN
	
	print(f"{help_bold}ASTERISK CLI COMMANDS:")
	print(f"\t{help_bold}LOGIN: {help_color}Login to your account")
	print(f"\t{help_bold}SINGUP: {help_color}Sign up for a new account")
	print(f"\t{help_bold}LOGOUT: {help_color}Log out of your account")
	print(f"\t{help_bold}EXIT: {help_color}exit the app")
	print(f"\t{help_bold}CLS: {help_color}clear the screen")
	print(f"\t{help_bold}CONNECT: {help_color}Connect to server (if online)")
	print(f"\t{help_sudo}VIEWDB: {help_color}View database contents")
	print(f"\t{help_sudo}SHUTDOWN: {help_color}Shutdown the server")
	# print(f"\t{help_bold}: {help_color}")
	print(f"\t{help_sudo}DELUSR: {help_color}Delete a user account. First argument is user to delete.")
	print(f"\t{help_bold}NEWGAME: {help_color}Create a new game lobby.")
	print(f"\t{help_bold}JOINGAME: {help_color}Join a game lobby. 1st argument is lobby ID, 2nd is password.")
	print(f"\t{help_bold}MSGUSR: {help_color}Send a message to another user. 1st arg is recipient, 2nd is message (in double quotes)")
	print(f"\t{help_bold}SYNC: {help_color}Update local data from server (messages, game updates, etc)")
	print(f"\t{help_bold}GAMEINFO: {help_color}Get info of current game lobby. -l flag for more stats")
	# print(f"{help_color}")
	# print(f"{help_color}")

def commandline_main(ca:ClientAgent):
	
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
		
		# Asterisk Prompt
		cmd_raw = input(f"{online_string} {user_string}{Fore.GREEN}* {Style.RESET_ALL}")
		words = parseIdx(cmd_raw, " \t")
		
		cmd_code = ensureWhitespace(cmd_raw, "[],")
		words_code = parseIdx(cmd_code, " \t")
		
		if len(words) < 1:
			continue
		cmd = words[0].str
		
		if cmd.upper() == "LOGIN":
			un = input("  Username: ")
			pw = input("  Password: ")
			if ca.login(un, pw):
				print(f"{Fore.GREEN}Successfully logged in{Style.RESET_ALL}")
			else:
				print(f"{Fore.RED}Failed to log in{Style.RESET_ALL}")
		elif cmd.upper() == "SIGNUP":
			un = input("  Username: ")
			em = input("     Email: ")
			pw = input("  Password: ")
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
		elif cmd.upper() == "CLS" or cmd.upper() == "CLEAR":
			if os.name == 'nt':
				os.system("cls")
			else:
				os.system("clear")
		elif cmd.upper() == "CONNECT":
			ca.connect_socket()
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
		elif cmd.upper() == "NEWGAME":
			if ca.new_game():
				print(f"{Fore.GREEN}Created game lobby{Style.RESET_ALL}")
			else:
				print(f"{Fore.RED}Failed to create game lobby.{Style.RESET_ALL}")
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
			
			# Autosync
			if CLI_AUTOSYNC:
				autosync(ca)
				
		elif cmd.upper() == "JOINGAME":
			
			# Check for number of arguments
			if len(words) < 3:
				print(f"{Fore.LIGHTRED_EX}Command JOINGAME requires 2 arguments (Lobby ID and password){Style.RESET_ALL}")
				continue
			
			# Ask to join lobby
			ca.join_game(words[1].str, words[2].str)
			
			# Autosync
			if CLI_AUTOSYNC:
				autosync(ca)
			
		elif cmd.upper() == "SYNC":
					
			# Execute sync
			ca.sync()
			
			if len(ca.notes) > 0:
				print(f"Messages:")
			for note in ca.notes:
				print(f"\t{Fore.LIGHTBLACK_EX}({note.timestamp_created}){Fore.YELLOW}[FROM: {note.sender}]{Style.RESET_ALL}{note.msg}")
			ca.notes = []
			
		elif cmd.upper() == "GAMEINFO":
			
			# Autosync
			if CLI_AUTOSYNC:
				autosync(ca)
			
			# Check for flags
			print_long = False
			if len(words) > 1:
				for tk in words:
					if tk.str == "-l":
						print_long = True
			
			# Check for no game
			if ca.game.id == -1:
				print(f"\t{Fore.LIGHTMAGENTA_EX}No game connected{Style.RESET_ALL}")
				continue
			
			# Print basic stats
			print(f"\tLobby  ID:{Fore.LIGHTBLUE_EX} {ca.game.id}{Style.RESET_ALL}")
			print(f"\tLobby pwd:{Fore.LIGHTBLUE_EX} {ca.game.password}{Style.RESET_ALL}")
			
			# Print long stats
			if print_long:
				print(f"\tPlayers:")
				for ply in ca.game.client_count.keys():
					num_client = ca.game.client_count[ply]
					print(f"\t\t{Fore.LIGHTBLUE_EX}{ply}{Style.RESET_ALL}: {num_client} client(s)")
				
				print("\tMap:")
				print(f"\t\tName: {Fore.LIGHTBLUE_EX}{ca.game.map.name}{Style.RESET_ALL}")
				print(f"\t\tCore  Size: {Fore.LIGHTBLUE_EX}{ca.game.map.core_size}{Style.RESET_ALL} cells")
				print(f"\t\tOuter Size: {Fore.LIGHTBLUE_EX}{ca.game.map.outer_size}{Style.RESET_ALL} cells")
				print(f"\t\tNo.  Planets: {Fore.LIGHTBLUE_EX}{len(ca.game.map.planets)}{Style.RESET_ALL} planets")
				print(f"\t\tNo. Naturals: {Fore.LIGHTBLUE_EX}{len(ca.game.map.naturals)}{Style.RESET_ALL} planets")
		
		elif cmd.upper() == "MAPINFO":
			
			# Autosync
			if CLI_AUTOSYNC:
				autosync(ca)
			
			# Check for flags
			print_long = False
			if len(words) > 1:
				for tk in words:
					if tk.str == "-l":
						print_long = True
			
			# Check for no game
			if ca.game.id == -1:
				print(f"\t{Fore.LIGHTMAGENTA_EX}No game connected{Style.RESET_ALL}")
				continue
			
			print(f"\tName: {Fore.LIGHTBLUE_EX}{ca.game.map.name}{Style.RESET_ALL}")
			print(f"\tCore  Size: {Fore.LIGHTBLUE_EX}{ca.game.map.core_size}{Style.RESET_ALL} cells")
			print(f"\tOuter Size: {Fore.LIGHTBLUE_EX}{ca.game.map.outer_size}{Style.RESET_ALL} cells")
			print(f"\tNo.  Planets: {Fore.LIGHTBLUE_EX}{len(ca.game.map.planets)}{Style.RESET_ALL} planets")
			if print_long:
				for idx, p in enumerate(ca.game.map.planets):
					print(f"{Fore.LIGHTBLACK_EX}\t\t[{idx}] Name: {Fore.LIGHTBLUE_EX}{p.name}{Style.RESET_ALL}")
					print(f"{Fore.LIGHTBLACK_EX}\t\t\tIs Capital: {Fore.LIGHTBLUE_EX}{p.capital}{Style.RESET_ALL}")
					print(f"{Fore.LIGHTBLACK_EX}\t\t\tPos: {Fore.LIGHTBLUE_EX}{p.cell}{Style.RESET_ALL}")
					print(f"{Fore.LIGHTBLACK_EX}\t\t\tSprite: {Fore.LIGHTBLUE_EX}{p.sprite}{Style.RESET_ALL}")
					print(f"{Fore.LIGHTBLACK_EX}\t\t\tbonuses:{Style.RESET_ALL}")
					for b in p.bonuses:
						print(f"{Fore.LIGHTBLACK_EX}\t\t\t\tType: {Fore.LIGHTGREEN_EX}{b.bonus_type}{Style.RESET_ALL}")
						print(f"{Fore.LIGHTBLACK_EX}\t\t\t\tValue: {Fore.LIGHTGREEN_EX}{b.value}{Style.RESET_ALL}")
					print(f"{Fore.LIGHTBLACK_EX}\t\t\tQuorum Size:{Fore.LIGHTBLUE_EX}{p.quorum}{Style.RESET_ALL} troops")
			print(f"\tNo. Naturals: {Fore.LIGHTBLUE_EX}{len(ca.game.map.naturals)}{Style.RESET_ALL} planets")
			if print_long:
				for idx, nf in enumerate(ca.game.map.naturals):
					print(f"{Fore.LIGHTBLACK_EX}\t\t[{idx}] Name: {Fore.LIGHTBLUE_EX}{nf.name}{Style.RESET_ALL}")
					print(f"{Fore.LIGHTBLACK_EX}\t\t\tType: {Fore.LIGHTBLUE_EX}{nf.nf_type}{Style.RESET_ALL}")
					print(f"{Fore.LIGHTBLACK_EX}\t\t\tSize: {Fore.LIGHTBLUE_EX}{len(nf.cellsx)}{Style.RESET_ALL} cells")
					print(f"{Fore.LIGHTBLACK_EX}\t\t\tX-positions: {Fore.LIGHTBLUE_EX}{nf.cellsx}{Style.RESET_ALL}")
					print(f"{Fore.LIGHTBLACK_EX}\t\t\tY-positions: {Fore.LIGHTBLUE_EX}{nf.cellsy}{Style.RESET_ALL}")
					print(f"{Fore.LIGHTBLACK_EX}\t\t\tdensity: {Fore.LIGHTBLUE_EX}{nf.density}{Style.RESET_ALL}")
		elif cmd.upper() == "ASSETS":
			
			# Autosync
			if CLI_AUTOSYNC:
				autosync(ca)
			
			# Check for flags
			print_long = False
			if len(words) > 1:
				for tk in words:
					if tk.str == "-l":
						print_long = True
			
			# Check for no game
			if ca.game.id == -1:
				print(f"\t{Fore.LIGHTMAGENTA_EX}No game connected{Style.RESET_ALL}")
				continue
			
			# Iterate over each faction
			for f in ca.game.factions:
				
				print(f"Faction: {Fore.LIGHTBLUE_EX}{f.name}{Style.RESET_ALL} ID={Fore.LIGHTBLUE_EX}{f.id}{Style.RESET_ALL}")
				print(f"\tShips: ")
				
				for idx, s in enumerate(f.ships):
					print(f"{Fore.LIGHTBLACK_EX}\t\t[{idx}] Name: {Fore.LIGHTBLUE_EX}{s.name}{Style.RESET_ALL}")
					print(f"{Fore.LIGHTBLACK_EX}\t\t\tID: {Fore.LIGHTBLUE_EX}{s.id}{Style.RESET_ALL}")
					print(f"{Fore.LIGHTBLACK_EX}\t\t\tCell: {Fore.LIGHTBLUE_EX}[{s.cell[0]}, {s.cell[1]}]{Style.RESET_ALL}")
					print(f"{Fore.LIGHTBLACK_EX}\t\t\tShip Type: {Fore.LIGHTBLUE_EX}{s.ship_type}{Style.RESET_ALL}")
					if print_long:
						print(f"{Fore.LIGHTBLACK_EX}\t\t\tTorpedo Inv.: {Fore.LIGHTBLUE_EX}{s.magazine}{Style.RESET_ALL}")
						print(f"{Fore.LIGHTBLACK_EX}\t\t\tCargo: {Fore.LIGHTBLUE_EX}{s.cargo}{Style.RESET_ALL}")
						print(f"{Fore.LIGHTBLACK_EX}\t\t\tFuel: {Fore.LIGHTBLUE_EX}{s.fuel_tank}{Style.RESET_ALL}")
						print(f"{Fore.LIGHTBLACK_EX}\t\t\tHP: {Fore.LIGHTBLUE_EX}{s.hp}{Style.RESET_ALL}")
						print(f"{Fore.LIGHTBLACK_EX}\t\t\tLoaded Torp. Tubes: {Fore.LIGHTBLUE_EX}{s.tubes_ready}{Style.RESET_ALL}")
						print(f"{Fore.LIGHTBLACK_EX}\t\t\tMovement rem.: {Fore.LIGHTBLUE_EX}{s.mvt_ready}{Style.RESET_ALL}")
			
		elif cmd.upper() == "ME":
			
			# Autosync
			if CLI_AUTOSYNC:
				autosync(ca)
			
			# Check for no game
			if ca.game.id == -1:
				print(f"\t{Fore.LIGHTMAGENTA_EX}No game connected{Style.RESET_ALL}")
				continue
			
			# Get user stats
			my_fid = ca.game.player_fid[ca.user]
			is_host = my_fid in ca.game.host_faction
			
			# Get active faction as a object
			f_act = ca.game.factions[ca.game.active_faction]
			my_fac = ca.game.factions[ca.game.fid_to_idx(my_fid)]
			
			print(f"\tYour Username: {Fore.LIGHTBLUE_EX}{ca.user}{Style.RESET_ALL}")
			print(f"\tYour Faction-ID: {Fore.LIGHTBLUE_EX}{my_fid}{Style.RESET_ALL}")
			print(f"\t\tFaction Name: {Fore.LIGHTBLUE_EX}{my_fac.name}{Style.RESET_ALL}")
			print(f"\t\tIs Active?: {Fore.LIGHTBLUE_EX}{my_fid == f_act.id}{Style.RESET_ALL}")
			print(f"\t\tIs Host?: {Fore.LIGHTBLUE_EX}{is_host}{Style.RESET_ALL}")
			print(f"\tYour account type: {Fore.LIGHTBLUE_EX}TODO{Style.RESET_ALL}") #TODO: Implement, get account type from server during login.
			
		elif cmd.upper() == "STATUS":
			
			# Autosync
			if CLI_AUTOSYNC:
				autosync(ca)
			
			# Check for flags
			print_long = False
			if len(words) > 1:
				for tk in words:
					if tk.str == "-l":
						print_long = True
			
			# Check for no game
			if ca.game.id == -1:
				print(f"\t{Fore.LIGHTMAGENTA_EX}No game connected{Style.RESET_ALL}")
				continue
			
			# Get lobby state as a string
			state_str = ""
			if ca.game.state == Game.GS_LOBBY:
				state_str = "GS_LOBBY"
			elif ca.game.state == Game.GS_RUN:
				state_str = "GS_RUN"
			elif ca.game.state == Game.GS_END:
				state_str = "GS_END"
			else:
				state_str = "?"
			
			# Get active faction as a string
			f = ca.game.factions[ca.game.active_faction]
			
			print(f"\tGame State: {Fore.LIGHTBLUE_EX}{state_str}{Style.RESET_ALL}")
			print(f"\tActive Faction: (id={Fore.LIGHTBLUE_EX}{f.id}{Style.RESET_ALL}, name={Fore.LIGHTBLUE_EX}{f.name}{Style.RESET_ALL})")
		elif cmd.upper() == "STARTGAME":
			ca.start_game()
			
			# Autosync
			if CLI_AUTOSYNC:
				autosync(ca)
			
		elif cmd.upper() == "YIELD":
			ca.yield_turn()
			
			# Autosync
			if CLI_AUTOSYNC:
				autosync(ca)
		
		elif cmd.upper() == "MOVESHIP":
			
			# Check for number of arguments
			if len(words_code) < 7:
				print(f"{Fore.LIGHTRED_EX}Command MOVESHIP requires 2 or more arguments (ship-id to move, cell to move to (in brackets)){Style.RESET_ALL}")
				continue
			
			if (words_code[2].str != '[') or (words_code[4].str != ',') or (words_code[6].str != ']'):
				print(f"{Fore.LIGHTRED_EX}Command MOVESHIP -improper syntax. Cell syntax: [r, q]){Style.RESET_ALL}")
				continue
			
			# msg = cmd_raw[words[2].idx:]
			# if msg[0] != "\"" or msg[-1] != "\"":
			# 	print(f"{Fore.LIGHTRED_EX}Command MOVESHIP - message must be contained in double quotes){Style.RESET_ALL}")
			# 	continue
			
			try:
				ship_id_test = int(words_code[1].str) # This value isn't used, but if it fails to become an int, syntax is wrong
				cell = [int(words_code[3].str), int(words_code[5].str)]
			except:
				print(f"{Fore.LIGHTRED_EX}Command MOVESHIP -improper syntax. Requires ship-id and cell in brackets.){Style.RESET_ALL}")
				continue
			
			# Find ship asset - get it's current cell
			idx = ca.game.get_asset_index(Game.OBJECT_SHIP, int(words_code[1].str), username=ca.user)
			start_cell = ca.game.factions[idx.fidx].ships[idx.sidx].cell
			
			# Run pathfinding algorithm
			ca.nav_grid.update(ca.game) #TODO: This is wildly repetative. Move this somewhere better evetually
			best_path = ca.nav_grid.pathfind(start_cell, cell, print_debug=ca.debug_state['pathfinding'])
			
			# Check for invalid path
			if best_path is None:
				print(f"  {Fore.RED}Failed to find a path to target destination.{Style.RESET_ALL}")
				continue
			
			if ca.debug_state['pathfinding']:
				print(best_path)
			
			# Move ship
			if not ca.move_ship(words_code[1].str, best_path):
				print(f"  {Fore.RED}Command failed. ({ca.reply}){Style.RESET_ALL}")
			
			# Autosync
			if CLI_AUTOSYNC:
				autosync(ca)
		
		elif cmd.upper() == "HELP_GENERAL":
			print_help()
		elif cmd.upper() == "DEBUG-MODE":
			
			# Look for flags
			if len(words) > 1:
				for tk in words[1:]:
					if tk.str == "-p" or tk.str == "--pathfinding":
						print("Client Debug: Pathfinding debug mode ON")
						ca.debug_state['pathfinding'] = True
					elif tk.str == "-v" or tk.str == "--view":
						print(f"Client Debug State:")
						for k in ca.debug_state.keys():
							v = ca.debug_state[k]
							print(f"    {k}: {Fore.CYAN}{v}{Style.RESET_ALL}")
					elif tk.str == "-x" or tk.str == "--alloff":
						for k in ca.debug_state.keys():
							ca.debug_state[k] = False
						print("Client Debug: All modes OFF")
					else:
						print(f"Unrecognized argument '{tk}'")
			
		elif cmd.upper() == "REFRESH-HELP":
			conf.reload_conf_data(load_help=True)
		elif cmd.upper() == "HELP":
			
			conf.help_data = conf.help_data
			conf.topic_data = conf.topic_data
			
			HELP_WIDTH = 80
			TABC = "    "
			
			color1 = Fore.WHITE # Body text
			color2 = Fore.LIGHTYELLOW_EX # Titles/headers
			color3 = Fore.YELLOW # Type specifiers, etc
			color4 = Fore.LIGHTBLACK_EX # brackets and accents
			
			hstr = ""
			
			list_all = False
			list_main = False
			list_game = False
			list_admin = False
			list_topics = False
			
			# Check for flags
			print_long = False
			if len(words) > 1:
				for tk in words:
					if tk.str == "-a" or tk.str == "--all":
						list_all = True
					elif tk.str == "-m" or tk.str == "--main":
						list_main = True
					elif tk.str == "-g" or tk.str == "--game":
						list_game = True
					elif tk.str == "-s" or tk.str == "--admin":
						list_admin = True
					elif tk.str == "-t" or tk.str == "--topics":
						list_topics = True
			if list_all:
				list_main = False
				list_game = False
				list_admin = False
				list_topics = False
			
			if list_all:
				
				# title
				hstr += color2 + "-"*HELP_WIDTH + Style.RESET_ALL + "\n"
				hstr += color2 + barstr(f"ALL HELP CONTENTS", HELP_WIDTH, "-", pad=True) + Style.RESET_ALL + "\n\n"
				
				# Commands header
				hstr += color2 + "\nALL COMMANDS:" + "\n"
				
				for cmd in conf.help_data.keys():
					
					desc = conf.help_data[cmd]['description']
					
					if conf.help_data[cmd]['admin_only']:
						hstr += f"{TABC}{Fore.CYAN}{cmd}{color1}: {desc}\n"
					elif len(conf.help_data[cmd]['context']) == 1 and conf.help_data[cmd]['context'][0] == "GAME":
						hstr += f"{TABC}{color3}{cmd}{color1}: {desc}\n"
					else:
						hstr += f"{TABC}{Fore.MAGENTA}{cmd}{color1}: {desc}\n"
				
				# Topics header
				hstr += color2 + "\nALL TOPICS:" + "\n"
				
				for tpc in conf.topic_data.keys():
					
					desc = conf.topic_data[tpc]['description']
					hstr += f"{TABC}{Fore.RED}{tpc}{color1}: {desc}\n"
				
				print(hstr)
				continue
			elif list_game:
				
				# title
				hstr += color2 + "-"*HELP_WIDTH + Style.RESET_ALL + "\n"
				hstr += color2 + barstr(f"GAME COMMANDS", HELP_WIDTH, "-", pad=True) + Style.RESET_ALL + "\n\n"
				
				for cmd in conf.help_data.keys():
					
					desc = conf.help_data[cmd]['description']
					
					if len(conf.help_data[cmd]['context']) == 1 and conf.help_data[cmd]['context'][0] == "GAME":
						hstr += f"{TABC}{color3}{cmd}{color1}: {desc}\n"
				
				print(hstr)
				continue
			
			elif list_admin:
				
				# title
				hstr += color2 + "-"*HELP_WIDTH + Style.RESET_ALL + "\n"
				hstr += color2 + barstr(f"ADMIN COMMANDS", HELP_WIDTH, "-", pad=True) + Style.RESET_ALL + "\n\n"
				
				for cmd in conf.help_data.keys():
					
					desc = conf.help_data[cmd]['description']
					
					if conf.help_data[cmd]['admin_only']:
						hstr += f"{TABC}{Fore.CYAN}{cmd}{color1}: {desc}\n"
				
				print(hstr)
				continue
			
			elif list_main:
				
				# title
				hstr += color2 + "-"*HELP_WIDTH + Style.RESET_ALL + "\n"
				hstr += color2 + barstr(f"GENERAL COMMANDS", HELP_WIDTH, "-", pad=True) + Style.RESET_ALL + "\n\n"
				
				for cmd in conf.help_data.keys():
					
					desc = conf.help_data[cmd]['description']
					
					if conf.help_data[cmd]['admin_only']:
						continue
					elif len(conf.help_data[cmd]['context']) == 1 and conf.help_data[cmd]['context'][0] == "GAME":
						continue
					else:
						hstr += f"{TABC}{Fore.MAGENTA}{cmd}{color1}: {desc}\n"
				
				print(hstr)
				continue
			
			elif list_topics:
				
				# title
				hstr += color2 + "-"*HELP_WIDTH + Style.RESET_ALL + "\n"
				hstr += color2 + barstr(f"ALL TOPICS", HELP_WIDTH, "-", pad=True) + Style.RESET_ALL + "\n\n"
				
				for tpc in conf.topic_data.keys():
					
					desc = conf.topic_data[tpc]['description']
					hstr += f"{TABC}{Fore.RED}{tpc}{color1}: {desc}\n"
				
				print(hstr)
				continue
			
			# Check for number of arguments
			if len(words_code) < 2:
				hcmd = "HELP"
			else:
				hcmd = words_code[1].str.upper()
			
			cmd_list = conf.help_data.keys()
			topic_list = conf.topic_data.keys()
			
			# Check if command is present in help data
			if (hcmd not in cmd_list) and (hcmd not in topic_list):
				
				# CHeck if need to add T/ prefix
				if (f"T/{hcmd}" not in topic_list):
					print(f"Failed to find command '{hcmd}' in help data.")
					continue
				else:
					hcmd = "T/"+hcmd
			
			if hcmd in cmd_list: # HCMD is a COMMAND name
			
				## Print help data:
				try:
					# title
					hstr += color2 + "-"*HELP_WIDTH + Style.RESET_ALL + "\n"
					hstr += color2 + barstr(f"{hcmd} Help", HELP_WIDTH, "-", pad=True) + Style.RESET_ALL + "\n\n"
					
					# Description
					hstr += f"{color2}Description:\n"
					hstr += f"{color1}{TABC}" + conf.help_data[hcmd]['description']+Style.RESET_ALL + "\n"
					
					# Arguments
					if len(conf.help_data[hcmd]['arguments']) > 0:
						hstr += f"{color2}\nArguments:\n"
						for ar in conf.help_data[hcmd]['arguments']:
							
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
					if len(conf.help_data[hcmd]['flags']) > 0:
						hstr += f"{color2}\nFlags:\n"
						for ar in conf.help_data[hcmd]['flags']:
							
							if ar["short"] != "" and ar["long"] != "":
								hstr += TABC + color1 + ar['short'] + f"{color4}," + color1 + ar["long"] + color4 + ": "
							elif ar['short'] != "":
								hstr += TABC + color1 + ar['short'] + color4 + ": "
							else:
								hstr += TABC + color1 + ar['long'] + color4 + ": "
								
							
							hstr += color1 + ar['description'] + "\n"
					
					# Examples
					if len(conf.help_data[hcmd]['examples']) > 0:
						hstr += f"{color2}\nExamples:\n"
						for ex_no, ar in enumerate(conf.help_data[hcmd]['examples']):
							
							hstr += f"{color1}{TABC}Ex {ex_no}:\n"
							hstr += TABC + TABC + color4 + ">> " + color3 + ar['command'] + "\n"
							hstr += TABC + TABC + color1 + "Desc: " + color1 + ar['description'] + "\n"							
					
					# Contexts
					hstr += f"{color2}\nContexts:\n"
					for ctx_mc in conf.help_data[hcmd]['context']:
						
						ctx = ctx_mc.upper()
						
						hstr += TABC + color1
						
						if ctx == "GAME":
							if conf.help_data[hcmd]['active_only']:
								hstr += "In-game (active faction only)"
							else:
								hstr += "In-game (all factions)"
						elif ctx == "OFFLINE":
							hstr += "Offline"
						elif ctx == "LOGIN":
							hstr += "Login screen"
						elif ctx == "MAIN":
							hstr += "Main menu (logged-in, prior to joining game)"
						elif ctx == "LOBBY":
							hstr += "Lobby"
						elif ctx == "RESULTS":
							hstr += "Results postmortem"
						
						hstr += "\n"
					
					# Restrictions
					hstr += f"{color2}\nRestrictions:\n"
					if conf.help_data[hcmd]['admin_only'] or conf.help_data[hcmd]['host_only']:
						if conf.help_data[hcmd]['admin_only']:
							hstr += f"{TABC}{Fore.CYAN}Admin only\n"
						if conf.help_data[hcmd]['host_only']:
							hstr += f"{TABC}{color3}Lobby-host only\n"
					else:
						hstr += f"{TABC}{color1}None\n"
						
					
					# See also
					if len(conf.help_data[hcmd]['see_also']) > 0:
						hstr += f"{color2}\nSee Also:\n{TABC}{color1}"
						add_comma = False
						for ar in conf.help_data[hcmd]['see_also']:
							
							if ar.upper() in cmd_list:
								
								if add_comma:
									hstr += ", "
								
								hstr += ar
								add_comma = True
					
					print(hstr)
				except Exception as e:
					print(f"Corrupt help data for selected entry '{hcmd}' ({e}).")
			
			else: # HCMD is a topic name
				
				## Print help data:
				try:
					# title
					hstr += color2 + "-"*HELP_WIDTH + Style.RESET_ALL + "\n"
					hstr += color2 + barstr(f"TOPIC: {hcmd}", HELP_WIDTH, "-", pad=True) + Style.RESET_ALL + "\n\n"
					
					# Description
					hstr += f"{color2}Topic Summary:\n"
					hstr += f"{color1}{TABC}" + conf.topic_data[hcmd]['description']+Style.RESET_ALL + "\n"
					
					# Body
					hstr += f"\n{color2}Body Text:\n"
					
					# Iterate over each body element
					for bd in conf.topic_data[hcmd]['body']:
						hstr += color1 + wrap_text(bd['data'], HELP_WIDTH) + "\n"
					
					# See also
					if len(conf.topic_data[hcmd]['see_also']) > 0:
						hstr += f"{color2}\nSee Also:\n{TABC}"
						add_comma = False
						for ar in conf.topic_data[hcmd]['see_also']:
							
							if ar.upper() in cmd_list:
								
								if add_comma:
									hstr += ", "
								
								hstr += ar
								add_comma = True
					
					print(hstr)
				except Exception as e:
					print(f"Corrupt help data for selected topic entry '{hcmd}' ({e}).")
				
		else:
			print(f"    Failed to recognize command {Fore.BLUE}<{Fore.YELLOW}{cmd}{Fore.BLUE}>{Style.RESET_ALL}")



if __name__ == '__main__':
	
	log = LogPile()
	
	# Create client agent
	ca = ClientAgent(log)
	ca.set_addr("localhost", 5555)
	ca.connect_socket()
	
	# Run CLI
	commandline_main(ca)


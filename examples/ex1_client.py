from pyfrost.pf_client import *
from colorama import Fore, Style
import os

if os.name != 'nt':
	import readline
	
CLI_AUTOSYNC = True


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
		
		# Main Prompt
		cmd_raw = input(f"{online_string} {user_string}{Fore.GREEN}> {Style.RESET_ALL}")
		words = parse_idx(cmd_raw, " \t")
		
		cmd_code = ensureWhitespace(cmd_raw, "[],")
		words_code = parse_idx(cmd_code, " \t")
		
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
			
		elif cmd.upper() == "SYNC":
					
			# Execute sync
			ca.sync()
			
			if len(ca.notes) > 0:
				print(f"Messages:")
			for note in ca.notes:
				print(f"\t{Fore.LIGHTBLACK_EX}({note.timestamp_created}){Fore.YELLOW}[FROM: {note.sender}]{Style.RESET_ALL}{note.msg}")
			ca.notes = []
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
		
		elif cmd.upper() == "HELP":
			
			HELP_WIDTH = 80
			TABC = "    "
			
			color1 = Fore.WHITE # Body text
			color2 = Fore.LIGHTYELLOW_EX # Titles/headers
			color3 = Fore.YELLOW # Type specifiers, etc
			color4 = Fore.LIGHTBLACK_EX # brackets and accents
			
			hstr = ""
			
			list_commands = False
			
			# Check for flags
			print_long = False
			if len(words) > 1:
				for tk in words:
					if tk.str == "-l" or tk.str == "--list":
						list_commands = True

			
			if list_commands:
				
				# title
				hstr += color2 + "-"*HELP_WIDTH + Style.RESET_ALL + "\n"
				hstr += color2 + barstr(f"ALL COMMANDS", HELP_WIDTH, "-", pad=True) + Style.RESET_ALL + "\n\n"
				
				for cmd in help_data.keys():
					desc = help_data[cmd]['description']
					hstr += f"{TABC}{Fore.CYAN}{cmd}{color1}: {desc}\n"
				
				print(hstr)
				continue
			
			# Check for number of arguments
			if len(words) < 2:
				hcmd = "HELP"
			else:
				hcmd = words[1].str.upper()
			
			cmd_list = help_data.keys()
			
			if hcmd in cmd_list: # HCMD is a COMMAND name
			
				## Print help data:
				try:
					# title
					hstr += color2 + "-"*HELP_WIDTH + Style.RESET_ALL + "\n"
					hstr += color2 + barstr(f"{hcmd} Help", HELP_WIDTH, "-", pad=True) + Style.RESET_ALL + "\n\n"
					
					# Description
					hstr += f"{color2}Description:\n"
					hstr += f"{color1}{TABC}" + help_data[hcmd]['description']+Style.RESET_ALL + "\n"
					
					# Arguments
					if len(help_data[hcmd]['arguments']) > 0:
						hstr += f"{color2}\nArguments:\n"
						for ar in help_data[hcmd]['arguments']:
							
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
					if len(help_data[hcmd]['flags']) > 0:
						hstr += f"{color2}\nFlags:\n"
						for ar in help_data[hcmd]['flags']:
							
							if ar["short"] != "" and ar["long"] != "":
								hstr += TABC + color1 + ar['short'] + f"{color4}," + color1 + ar["long"] + color4 + ": "
							elif ar['short'] != "":
								hstr += TABC + color1 + ar['short'] + color4 + ": "
							else:
								hstr += TABC + color1 + ar['long'] + color4 + ": "
								
							
							hstr += color1 + ar['description'] + "\n"
					
					# Examples
					if len(help_data[hcmd]['examples']) > 0:
						hstr += f"{color2}\nExamples:\n"
						for ex_no, ar in enumerate(help_data[hcmd]['examples']):
							
							hstr += f"{color1}{TABC}Ex {ex_no}:\n"
							hstr += TABC + TABC + color4 + ">> " + color3 + ar['command'] + "\n"
							hstr += TABC + TABC + color1 + "Desc: " + color1 + ar['description'] + "\n"
						
						hstr += "\n"
					
					
					# See also
					if len(help_data[hcmd]['see_also']) > 0:
						hstr += f"{color2}\nSee Also:\n{TABC}{color1}"
						add_comma = False
						for ar in help_data[hcmd]['see_also']:
							
							if ar.upper() in cmd_list:
								
								if add_comma:
									hstr += ", "
								
								hstr += ar
								add_comma = True
					
					print(hstr)
				except Exception as e:
					print(f"Corrupt help data for selected entry '{hcmd}' ({e}).")
				
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


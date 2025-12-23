#!/usr/bin/env python

import sqlite3
import argparse
from colorama import Fore, Style
from pyfrost.base import username_follows_rules, valid_email
from getpass import getpass
import hashlib
import sys
import datetime

#TODO: Verify that email and username aren't already claimed
def main():
	
	# Read input argument
	parser = argparse.ArgumentParser()
	parser.add_argument('db_name')
	args = parser.parse_args()

	# Access database - create if doesn't exist
	con = sqlite3.connect(args.db_name)

	is_first = True

	# Create primary table
	cur = con.cursor()
	try:
		cur.execute("CREATE TABLE userdata(username, password, acct_id, email_addr, verified, acct_type, join_date)")
		print(f"{Fore.CYAN}Initialized table USERDATA{Style.RESET_ALL}")
	except sqlite3.OperationalError: # Table already exists!
		print(f"{Fore.CYAN}Found existing table USERDATA{Style.RESET_ALL}")
		
		# Check if accounts already exist
		cur.execute("SELECT MAX(acct_id) FROM userdata")
		fd = cur.fetchall()
		if fd[0][0] is not None:
			print(f"{Fore.CYAN}Found existing accounts{Style.RESET_ALL}")
			is_first = False
		
		

	# List of acceptable account types
	account_types = ["ADMIN", "STANDARD", "LOW", "RESTRICTED"]

	# Console constants
	prompt_color = Fore.YELLOW
	tab_char = "    "

	def level_str(acct_level:str):
		
		if acct_level.upper() == "ADMIN":
			return f"{Fore.GREEN}ADMIN{Style.RESET_ALL}"
		elif acct_level.upper() == "STANDARD":
			return f"{Fore.LIGHTBLUE_EX}STANDARD{Style.RESET_ALL}"
		elif acct_level.upper() == "LOW":
			return f"{Fore.LIGHTRED_EX}LOW{Style.RESET_ALL}"
		elif acct_level.upper() == "RESTRICTED":
			return f"{Fore.LIGHTRED_EX}RESTRICTED{Style.RESET_ALL}"
		else:
			return f"{Fore.LIGHTRED_EX}???{Style.RESET_ALL}"

	# Prompt user for account data
	while True:
		
		# Ask for new account details
		if is_first:
			acct_type = "ADMIN"
			print(f"{prompt_color}{tab_char}Account type: {level_str(acct_type)} {Fore.LIGHTBLACK_EX}(At least one admin account must be added){Style.RESET_ALL}")
			is_first = False
		else:
			
			# Loop until account type provided
			while True:
				rt = input(f"{prompt_color}{tab_char}Account type (ADMIN, STANDARD, LOW, RESTRICTED):{Style.RESET_ALL} ")
				if rt.upper() in account_types:
					acct_type = rt.upper()
					break
				else:
					print(f"{Fore.RED}{tab_char}  Invalid account type '{rt}' provided.{Style.RESET_ALL}")
		
		# Get email
		while True:
			rt = input(f"{prompt_color}{tab_char}[{level_str(acct_type)}{prompt_color}] Email: {Style.RESET_ALL}")
			if valid_email(rt):
				email = rt
				break
			else:
				print(f"{Fore.RED}{tab_char}  Invalid email '{rt}' provided.{Style.RESET_ALL}")
		
		# Get username
		while True:
			rt = input(f"{prompt_color}{tab_char}[{level_str(acct_type)}{prompt_color}] Username: {Style.RESET_ALL}")
			if username_follows_rules(rt):
				username = rt
				break
			else:
				print(f"{Fore.RED}{tab_char}  Invalid username '{rt}' provided.{Style.RESET_ALL}")
		
		# Get password
		while True:
			pwd = getpass(prompt=f"{prompt_color}{tab_char}[{level_str(acct_type)}{prompt_color}] password: {Style.RESET_ALL}")
			pwd2 = getpass(prompt=f"{prompt_color}{tab_char}[{level_str(acct_type)}{prompt_color}] Retype password: {Style.RESET_ALL}")
		
			if pwd != pwd2:
				print(f"{Fore.RED}{tab_char}  Passwords do not match.{Style.RESET_ALL}")
			else:
				break
		
		password_hash = hashlib.sha256(pwd.encode()).hexdigest()
		
		# Lookup highest account ID
		cur.execute("SELECT MAX(acct_id) FROM userdata")
		fd = cur.fetchall()
		if fd[0][0] is None:
			next_ID = 0
		else:
			try:
				next_ID = int(fd[0][0])+1
			except:
				print(f"{Fore.RED}{tab_char}Failed to access account ID from database.{Style.RESET_ALL}")
				sys.exit()
		
		# Add to database
		cur.execute("INSERT INTO userdata (username, password, acct_id, email_addr, verified, acct_type, join_date) VALUES (?, ?, ?, ?, ?, ?, ?)", (username, password_hash, next_ID , email, "No", acct_type, str(datetime.now())))
		
		# Check if user wishes to add more users
		rt = input(f"{Fore.CYAN}Add more users? (Y/n): {Style.RESET_ALL}")
		if rt.upper() != "Y":
			break

	con.commit()
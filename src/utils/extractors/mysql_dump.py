"""MySQL dumper — connects with valid credentials and extracts database structure and contents."""

import json
import os
import socket
import struct
import hashlib


BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class MySQLDumper:
    """Connects to MySQL with known credentials and dumps databases, tables, and row data."""

    def __init__(self, ip: str, port: int, username: str, password: str):
        """Initialize with target connection details.

        Args:
            ip (str): Target IP address.
            port (int): MySQL port.
            username (str): Valid username.
            password (str): Valid password.
        """
        self.ip = ip
        self.port = port
        self.username = username
        self.password = password

    def run(self):
        """Connect, enumerate databases and tables, dump contents, save to JSON.

        Returns:
            dict: Full dump structure keyed by database name.
        """
        print(f"\n  [DUMP] Starting MySQL dump on {self.ip}:{self.port} as {self.username}")
        try:
            import mysql.connector
        except ImportError:
            print(f"  [DUMP] mysql-connector-python not installed — run: pip install mysql-connector-python")
            return {'status': 'no_connector'}

        dump = {}
        try:
            conn = mysql.connector.connect(
                host=self.ip,
                port=self.port,
                user=self.username,
                password=self.password,
                connection_timeout=5,
            )
            cursor = conn.cursor()

            databases = self._get_databases(cursor)
            print(f"  [DUMP] Found {len(databases)} databases: {databases}")

            for db in databases:
                if db in ('information_schema', 'performance_schema', 'sys', 'mysql'):
                    continue
                print(f"  [DUMP] Dumping database: {db}")
                dump[db] = self._dump_database(conn, cursor, db)

            cursor.close()
            conn.close()

            self._save(dump)
            print(f"  [DUMP] Saved to reports/mysql_dump.json")
            return {'status': 'success', 'databases': list(dump.keys())}

        except Exception as e:
            print(f"  [DUMP] Connection failed: {e}")
            return {'status': 'failed', 'error': str(e)}

    def _get_databases(self, cursor) -> list:
        """Retrieve list of all databases on the server.

        Args:
            cursor: Active MySQL cursor.

        Returns:
            list: Database names.
        """
        cursor.execute("SHOW DATABASES")
        return [row[0] for row in cursor.fetchall()]

    def _dump_database(self, conn, cursor, db: str) -> dict:
        """Dump all tables and their contents from a single database.

        Args:
            conn: Active MySQL connection.
            cursor: Active MySQL cursor.
            db (str): Database name to dump.

        Returns:
            dict: Tables with their columns and rows.
        """
        result = {}
        try:
            cursor.execute(f"USE `{db}`")
            cursor.execute("SHOW TABLES")
            tables = [row[0] for row in cursor.fetchall()]
            print(f"  [DUMP] {db} — {len(tables)} tables: {tables}")

            for table in tables:
                result[table] = self._dump_table(cursor, table)
        except Exception as e:
            result['_error'] = str(e)
        return result

    def _dump_table(self, cursor, table: str) -> dict:
        """Dump columns and up to 500 rows from a single table.

        Args:
            cursor: Active MySQL cursor.
            table (str): Table name to dump.

        Returns:
            dict: Columns list and rows list.
        """
        try:
            cursor.execute(f"SELECT * FROM `{table}` LIMIT 500")
            columns = [desc[0] for desc in cursor.description]
            rows = [list(row) for row in cursor.fetchall()]
            print(f"  [DUMP] {table} — {len(rows)} rows, columns: {columns}")
            return {'columns': columns, 'rows': rows}
        except Exception as e:
            return {'_error': str(e)}

    def _save(self, dump: dict):
        """Write dump to reports/mysql_dump.json.

        Args:
            dump (dict): Full database dump structure.
        """
        reports_path = os.path.join(BASE_DIR, '..', '..', '..', 'reports', 'mysql_dump.json')
        os.makedirs(os.path.dirname(reports_path), exist_ok=True)
        with open(reports_path, 'w', encoding='utf-8') as f:
            json.dump(dump, f, indent=4, default=str)

import sqlite3
import os
from datetime import datetime

DB_FOLDER = "database"
DB_PATH = os.path.join(DB_FOLDER, "scans.db")


def create_database():
	os.makedirs(DB_FOLDER, exist_ok=True)

	connection = sqlite3.connect(DB_PATH)
	cursor = connection.cursor()

	cursor.execute("""
		CREATE TABLE IF NOT EXISTS scans (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_type TEXT NOT NULL,
			input_data TEXT NOT NULL,
			risk_level TEXT NOT NULL,
			risk_score INTEGER NOT NULL,
			result TEXT NOT NULL,
			scan_time TEXT NOT NULL
		)
	""")

	connection.commit()
	connection.close()


def save_scan(scan_type, input_data, risk_level, risk_score, result):
	create_database()

	connection = sqlite3.connect(DB_PATH)
	cursor = connection.cursor()

	cursor.execute("""
		INSERT INTO scans
		(scan_type, input_data, risk_level, risk_score, result, scan_time)
		VALUES (?, ?, ?, ?, ?, ?)
	""", (
		scan_type,
		input_data,
		risk_level,
		risk_score,
		result,
		datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	))

	connection.commit()
	connection.close()


def get_scans():
	create_database()

	connection = sqlite3.connect(DB_PATH)
	cursor = connection.cursor()

	cursor.execute("""
		SELECT * FROM scans ORDER BY id DESC
	""")

	records = cursor.fetchall()
	connection.close()

	return records

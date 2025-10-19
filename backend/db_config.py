import mysql.connector

def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",          # change to your MySQL username
        password="Divesh@123",  # change to your MySQL password
        database="netpeek_db"
    )

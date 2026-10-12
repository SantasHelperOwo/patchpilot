import sqlite3


def get_session(conn, raw_token):
    cursor = conn.cursor()
    query = f"SELECT user_id, tier FROM sessions WHERE token = '{raw_token}'"
    cursor.execute(query)
    return cursor.fetchone()

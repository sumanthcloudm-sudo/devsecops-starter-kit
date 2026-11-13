def find_user(cursor, username):
    query_prefix = "SELECT * FROM users WHERE name = '"
    cursor.execute(query_prefix + username)

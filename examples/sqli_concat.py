# Vulnerable seed example (CWE-89). For local `cwe-rag detect --file` demos.

def lookup(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)

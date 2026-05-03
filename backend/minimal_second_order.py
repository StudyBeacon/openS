import sqlite3

# Minimal second-order SQL injection test
def setup():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (name TEXT, bio TEXT)")
    conn.execute("INSERT INTO users VALUES ('alice', 'safe')")
    return conn

def store_bio(conn, name, bio):
    # Step 1: store user-controlled bio (tainted)
    conn.execute("UPDATE users SET bio = ? WHERE name = ?", (bio, name))
    conn.commit()

def get_bio(conn, name):
    # Step 2: retrieve the stored bio
    cur = conn.execute("SELECT bio FROM users WHERE name = ?", (name,))
    return cur.fetchone()[0]

def search_by_bio(conn, keyword):
    # Step 3: use retrieved bio in unsafe dynamic query
    query = f"SELECT name FROM users WHERE bio = '{keyword}'"   # SINK
    return conn.execute(query).fetchall()

def test():
    conn = setup()
    # Simulate attacker-controlled input
    malicious_bio = input()
    store_bio(conn, "alice", malicious_bio)
    stored = get_bio(conn, "alice")
    result = search_by_bio(conn, stored)   # second-order injection
    print(result)

if __name__ == "__main__":
    test()

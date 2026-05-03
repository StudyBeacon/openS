import os

def vulnerable_function(user_input):
    # SQL injection vulnerability
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    print(f"Executing: {query}")

vulnerable_function("admin' OR '1'='1")

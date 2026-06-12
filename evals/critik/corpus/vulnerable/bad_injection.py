# Intentionally vulnerable file for testing
import os
import subprocess

def get_user(user_id):
    db.execute(f"SELECT * FROM users WHERE id = {user_id}")

def search(query):
    db.execute("SELECT * FROM items WHERE name = '" + query + "'")

def process(data):
    result = eval(data)
    return result

def run_command(cmd):
    subprocess.call(cmd, shell=True)

def legacy_run(command):
    os.system(command)

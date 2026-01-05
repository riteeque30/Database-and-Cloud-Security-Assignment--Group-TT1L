import streamlit as st
import sqlite3
import hashlib
import re
import logging
import shutil
import os
from datetime import datetime

logging.basicConfig(
    filename="medivault.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

DB_FILE = "medivault.db"
BACKUP_DIR = "backup"
BACKUP_FILE = f"{BACKUP_DIR}/medivault_backup.db"
MAX_LOGIN_ATTEMPTS = 5

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def validate_password(password):
    if len(password) < 8:
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    if not any(not c.isalnum() for c in password):
        return False
    return True

def validate_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def sanitize_input(value):
    return value.replace("'", "''")

def create_connection():
    return sqlite3.connect(DB_FILE)

def create_tables(conn):
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT,
        is_locked INTEGER DEFAULT 0
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS doctors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        department TEXT,
        availability TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS appointments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        doctor_id INTEGER,
        patient_name TEXT,
        patient_email TEXT,
        appointment_date TEXT
    )""")
    conn.commit()

def seed_doctors(conn):
    doctors = [
        ("Dr Amir", "Cardiology", "Mon-Fri"),
        ("Dr Siti", "Pediatrics", "Mon-Thu"),
        ("Dr Kumar", "General Medicine", "Daily")
    ]
    c = conn.cursor()
    for d in doctors:
        c.execute("INSERT OR IGNORE INTO doctors (name, department, availability) VALUES (?,?,?)", d)
    conn.commit()

def sign_up(conn, username, password, role):
    if not validate_password(password):
        st.error("Weak password")
        return
    try:
        conn.execute(
            "INSERT INTO users (username, password, role) VALUES (?,?,?)",
            (sanitize_input(username), hash_password(password), role)
        )
        conn.commit()
        st.success("Account created")
    except:
        st.error("Username exists")

def lock_account(conn, username):
    conn.execute("UPDATE users SET is_locked=1 WHERE username=?", (username,))
    conn.commit()

def authenticate(conn, username, password):
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (sanitize_input(username),))
    user = c.fetchone()

    if not user:
        return False, None
    if user[4] == 1:
        st.error("Account locked")
        return False, None

    if hash_password(password) == user[2]:
        st.session_state.login_attempts = 0
        return True, user[3]

    st.session_state.login_attempts += 1
    if st.session_state.login_attempts >= MAX_LOGIN_ATTEMPTS:
        lock_account(conn, username)
        st.error("Account locked")
    return False, None

def book_appointment(conn, doctor_id, name, email, date):
    conn.execute(
        "INSERT INTO appointments (doctor_id, patient_name, patient_email, appointment_date) VALUES (?,?,?,?)",
        (doctor_id, sanitize_input(name), sanitize_input(email), str(date))
    )
    conn.commit()

def fetch_appointments(conn):
    return conn.execute("""
        SELECT a.id, d.name, a.patient_name, a.patient_email, a.appointment_date
        FROM appointments a JOIN doctors d ON a.doctor_id = d.id
    """).fetchall()

def backup_database():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    shutil.copy(DB_FILE, BACKUP_FILE)

def main():
    st.title("MediVault - Secure Medical Appointment System")

    if "login_attempts" not in st.session_state:
        st.session_state.login_attempts = 0
    if "role" not in st.session_state:
        st.session_state.role = None

    conn = create_connection()
    create_tables(conn)
    seed_doctors(conn)

    menu = ["Home", "Login", "Sign Up"]
    if st.session_state.role:
        menu = ["Home", "Book Appointment", "Logout"]
    if st.session_state.role == "admin":
        menu.insert(2, "View Appointments")

    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Home":
        st.write("Secure healthcare system with database security controls")

    elif choice == "Sign Up":
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        r = st.selectbox("Role", ["patient", "admin"])
        if st.button("Register"):
            sign_up(conn, u, p, r)

    elif choice == "Login":
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        if st.button("Login"):
            ok, role = authenticate(conn, u, p)
            if ok:
                st.session_state.role = role
                st.success("Login successful")

    elif choice == "Book Appointment":
        name = st.text_input("Patient Name")
        email = st.text_input("Email")
        date = st.date_input("Appointment Date")
        doctors = conn.execute("SELECT * FROM doctors").fetchall()
        doc = st.selectbox("Doctor", doctors, format_func=lambda x: x[1])
        if st.button("Book"):
            if validate_email(email):
                book_appointment(conn, doc[0], name, email, date)
                st.success("Appointment booked")
            else:
                st.error("Invalid email")

    elif choice == "View Appointments":
        st.table(fetch_appointments(conn))

    elif choice == "Logout":
        st.session_state.clear()
        st.success("Logged out")

    conn.close()
    backup_database()

if __name__ == "__main__":
    main()

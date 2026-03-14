import sqlite3
import os

DATABASE_URL = "scams.db"

def get_db():
    conn = sqlite3.connect(DATABASE_URL, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    conn = sqlite3.connect(DATABASE_URL)
    cursor = conn.cursor()
    
    # Create the scams table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scam_type TEXT NOT NULL,
            description TEXT NOT NULL,
            screenshot_path TEXT,
            target_phone TEXT,
            target_email TEXT,
            target_website TEXT,
            experienced_count INTEGER DEFAULT 0,
            suspicious_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Create the safety tips table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS safety_tips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            category TEXT NOT NULL
        )
    """)
    
    conn.commit()
    
    # Seed standard safety tips
    cursor.execute("SELECT COUNT(*) FROM safety_tips")
    if cursor.fetchone()[0] == 0:
        tips = [
            ("Verify the Source", "Always double-check the sender's email address or phone number. Scammers often use addresses that look similar to official ones.", "General"),
            ("Never Share OTPs", "Banks and legitimate services will never ask for your One-Time Password. Do not share it with anyone.", "OTP Scams"),
            ("Too Good to Be True", "If an online deal or job offer seems too good to be true, it probably is a scam. Research the company before proceeding.", "Job Scams"),
            ("Beware of Urgent Requests", "Scammers create a sense of urgency to force you into making quick decisions without thinking.", "General"),
            ("Use Secure Connections", "When shopping online, look for 'https' in the URL and a padlock icon to ensure your connection is secure.", "Online Shopping Scams"),
        ]
        cursor.executemany("INSERT INTO safety_tips (title, content, category) VALUES (?, ?, ?)", tips)
        conn.commit()

    conn.close()

if __name__ == "__main__":
    init_db()
    print("Database initialized successfully.")

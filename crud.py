import sqlite3
from typing import List, Optional

def create_scam_report(
    db: sqlite3.Connection,
    scam_type: str,
    description: str,
    screenshot_path: Optional[str] = None,
    target_phone: Optional[str] = None,
    target_email: Optional[str] = None,
    target_website: Optional[str] = None
) -> sqlite3.Row:
    cursor = db.cursor()
    cursor.execute("""
        INSERT INTO scams (scam_type, description, screenshot_path, target_phone, target_email, target_website)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (scam_type, description, screenshot_path, target_phone, target_email, target_website))
    db.commit()
    report_id = cursor.lastrowid
    if report_id is None:
        raise RuntimeError("Failed to retrieve the inserted report ID.")
    return get_scam_report(db, report_id)

def get_scam_report(db: sqlite3.Connection, report_id: int) -> sqlite3.Row:
    cursor = db.cursor()
    cursor.execute("SELECT * FROM scams WHERE id = ?", (report_id,))
    return cursor.fetchone()

def search_reports(db: sqlite3.Connection, query: str) -> List[sqlite3.Row]:
    cursor = db.cursor()
    search_term = f"%{query}%"
    cursor.execute("""
        SELECT * FROM scams 
        WHERE target_phone LIKE ? 
           OR target_email LIKE ? 
           OR target_website LIKE ?
        ORDER BY created_at DESC
    """, (search_term, search_term, search_term))
    return cursor.fetchall()

def get_heatmap_stats(db: sqlite3.Connection) -> List[sqlite3.Row]:
    cursor = db.cursor()
    cursor.execute("""
        SELECT scam_type, COUNT(*) as count 
        FROM scams 
        GROUP BY scam_type
        ORDER BY count DESC
    """)
    return cursor.fetchall()

def vote_scam(db: sqlite3.Connection, report_id: int, vote_type: str) -> Optional[sqlite3.Row]:
    cursor = db.cursor()
    if vote_type == 'experienced':
        cursor.execute("UPDATE scams SET experienced_count = experienced_count + 1 WHERE id = ?", (report_id,))
    elif vote_type == 'suspicious':
        cursor.execute("UPDATE scams SET suspicious_count = suspicious_count + 1 WHERE id = ?", (report_id,))
    else:
        return None
    
    db.commit()
    return get_scam_report(db, report_id)

def get_safety_tips(db: sqlite3.Connection) -> List[sqlite3.Row]:
    cursor = db.cursor()
    cursor.execute("SELECT * FROM safety_tips")
    return cursor.fetchall()

import threading
import time
import json
from database import get_db_connection, add_reclassification_history, add_notification
from analyzer import analyze_url

def check_for_reclassifications():
    print("Running background reclassification check...")
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get unique domains from recent logs
        cursor.execute("SELECT DISTINCT domain FROM Logs ORDER BY id DESC LIMIT 100")
        domains = [r[0] for r in cursor.fetchall()]
        
        for domain in domains:
            # Re-analyze domain
            url = f"http://{domain}"
            new_status, breakdown = analyze_url(url)
            
            # Check the most recent status for this domain in Logs
            cursor.execute("SELECT status FROM Logs WHERE domain = %s ORDER BY timestamp DESC LIMIT 1", (domain,))
            last_record = cursor.fetchone()
            if not last_record:
                continue
                
            old_status = last_record[0]
            
            if new_status != old_status:
                reason = f"Automated background scan reclassified this domain from {old_status} to {new_status}."
                add_reclassification_history(domain, old_status, new_status, reason)
                
                # Notify users who visited this domain
                cursor.execute("SELECT DISTINCT user_id FROM Logs WHERE domain = %s AND user_id IS NOT NULL", (domain,))
                users = cursor.fetchall()
                for user in users:
                    msg = f"A website you visited ({domain}) changed status from {old_status} to {new_status}."
                    add_notification(user[0], 'RECLASSIFICATION', msg, domain)
                    
        conn.close()
    except Exception as e:
        print(f"Error in background reclassification task: {e}")

def start_scheduler():
    def run_loop():
        # Delay the first run slightly to allow the server to start
        time.sleep(10)
        while True:
            check_for_reclassifications()
            # Run every 6 hours (21600 seconds) to avoid spamming APIs in prod
            time.sleep(21600) 

    # Start the background thread
    thread = threading.Thread(target=run_loop, daemon=True)
    thread.start()

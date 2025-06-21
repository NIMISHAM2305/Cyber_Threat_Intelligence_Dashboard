from apscheduler.schedulers.background import BackgroundScheduler
from feeds import fetch_threat_feed
import atexit

scheduler = BackgroundScheduler()

def start_scheduler():
    # Schedule threat feed fetch every 10 minutes
    scheduler.add_job(func=fetch_threat_feed, trigger="interval", minutes=10)
    scheduler.start()
    print("Scheduler started: Fetching threat feed every 10 minutes.")

    # Shutdown scheduler on exit
    atexit.register(lambda: scheduler.shutdown())

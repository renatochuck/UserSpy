import aiohttp
import asyncio
import argparse
import random
import csv
import json
import logging
import requests
import time
import sqlite3
import socket
import ssl
import nest_asyncio
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from fake_useragent import UserAgent
from bs4 import BeautifulSoup

# Apply asyncio fix for Kali Linux
nest_asyncio.apply()

# Console UI
console = Console()

# ASCII Banner
BANNER = """
███████╗ █████╗ ██╗  ██╗ █████╗ ███╗   ██╗██╗
██╔════╝██╔══██╗██║  ██║██╔══██╗████╗  ██║██║
███████╗███████║███████║███████║██╔██╗ ██║██║
╚════██║██╔══██║██╔══██║██╔══██║██║╚██╗██║██║
███████║██║  ██║██║  ██║██║  ██║██║ ╚████║██║
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝
"""
console.print(f"[bold red]{BANNER}[/bold red]")

# Logging setup
LOG_FILE = "error_log.txt"
logging.basicConfig(filename=LOG_FILE, level=logging.ERROR, format="%(asctime)s - %(levelname)s - %(message)s")

# Load rotating User-Agents with fallback
try:
    ua = UserAgent()
except:
    ua = UserAgent(use_cache_server=False)

# Define target sites
SITES = {
    "GitHub": "https://github.com/{}",
    "Twitter": "https://twitter.com/{}",
    "Instagram": "https://www.instagram.com/{}",
    "LinkedIn": "https://www.linkedin.com/in/{}",
    "YouTube": "https://www.youtube.com/{}",
    "Reddit": "https://www.reddit.com/user/{}",
    "Pinterest": "https://www.pinterest.com/{}",
    "Snapchat": "https://www.snapchat.com/add/{}",
    "Facebook": "https://www.facebook.com/{}",
    "Medium": "https://medium.com/@{}",
    "TikTok": "https://www.tiktok.com/@{}",
}

# Database Setup
DB_FILE = "results.db"

def create_db():
    """Create SQLite database to store results."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY,
            platform TEXT,
            username TEXT,
            profile_url TEXT
        )
    """)
    conn.commit()
    conn.close()

# SSL Handling
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

async def get_session():
    """Create an async session with proxy support."""
    headers = {"User-Agent": ua.random}
    timeout = aiohttp.ClientTimeout(total=15)
    session = aiohttp.ClientSession(headers=headers, timeout=timeout, connector=aiohttp.TCPConnector(ssl=ssl_context))
    return session

# Check username availability
async def check_username(session, username, site_name, url):
    """Check if the username exists on the platform."""
    try:
        async with session.get(url.format(username)) as response:
            if response.status == 200:
                return site_name, url.format(username)
    except Exception as e:
        logging.error(f"Error checking {site_name}: {e}")
    return None

# Run async username search
async def search_username(username):
    """Perform an async search across multiple platforms."""
    console.print(f"\n[bold yellow]🔍 Searching for username: {username}[/bold yellow]\n")

    results = []
    async with await get_session() as session:
        tasks = [check_username(session, username, site, url) for site, url in SITES.items()]
        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning platforms...", total=len(tasks))
            for result in asyncio.as_completed(tasks):
                found = await result
                if found:
                    results.append(found)
                progress.update(task, advance=1)

    save_results(username, results)
    display_results(username, results)

# Save results in JSON & CSV
def save_results(username, results):
    """Save results in JSON and CSV format."""
    json_filename = f"{username}_results.json"
    csv_filename = f"{username}_results.csv"

    with open(json_filename, "w", encoding="utf-8") as file:
        json.dump([{ "Platform": site, "URL": url } for site, url in results], file, indent=4)

    with open(csv_filename, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["Platform", "Profile URL"])
        for site, url in results:
            writer.writerow([site, url])

# Display results
def display_results(username, results):
    """Display results in a console table."""
    table = Table(title=f"🔍 Results for {username}")
    table.add_column("Platform", style="bold magenta")
    table.add_column("Profile URL", style="bold green")
    for site, url in results:
        table.add_row(site, url)
    console.print(table)

# Main function
def main():
    create_db()
    parser = argparse.ArgumentParser(description="Sahani - Ultimate Username Enumeration Tool")
    parser.add_argument("username", help="Username to search for")
    args = parser.parse_args()

    asyncio.run(search_username(args.username))

if __name__ == "__main__":
    main()
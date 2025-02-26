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
import sqlite3
from concurrent.futures import ThreadPoolExecutor
import socket
from bs4 import BeautifulSoup

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
console.print(BANNER, style="bold red")

# Logging setup
LOG_FILE = "error_log.txt"
logging.basicConfig(filename=LOG_FILE, level=logging.ERROR, format="%(asctime)s - %(levelname)s - %(message)s")

# Load rotating User-Agents
ua = UserAgent()

# Username enumeration sites
SITES = {
    "GitHub": "https://github.com/{}",
    "Twitter": "https://twitter.com/{}",
    "Instagram": "https://www.instagram.com/{}",
    "LinkedIn": "https://www.linkedin.com/in/{}",
}

async def check_username(session, site_name, site_url, username):
    url = site_url.format(username)
    headers = {"User-Agent": ua.random}
    try:
        async with session.get(url, headers=headers, timeout=10) as response:
            if response.status == 200:
                return site_name, url
    except Exception as e:
        logging.error(f"Error checking {site_name}: {e}")
    return None

async def main(username):
    console.print(f"[bold cyan]Checking username:[/bold cyan] {username}")
    async with aiohttp.ClientSession() as session:
        tasks = [check_username(session, site, url, username) for site, url in SITES.items()]
        results = await asyncio.gather(*tasks)
    
    table = Table(title="Results")
    table.add_column("Site", style="cyan")
    table.add_column("Profile URL", style="magenta")
    
    found = [res for res in results if res]
    if found:
        for site_name, url in found:
            table.add_row(site_name, url)
        console.print(table)
    else:
        console.print("[bold red]No profiles found.[/bold red]")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Find user profiles across multiple sites.")
    parser.add_argument("username", help="Username to search for")
    args = parser.parse_args()
    asyncio.run(main(args.username))

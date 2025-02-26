Here’s the updated `README.md` with an added section for **Output**:

```markdown
# UserSpy - Ultimate Username Enumeration Tool

## Introduction

**UserSpy** is an advanced username enumeration tool designed to search for a given username across various social media platforms and websites. It also provides additional features such as brute force login, SQL injection check, XSS detection, and port scanning. The tool supports asynchronous operations and utilizes rotating proxies to avoid IP bans while scanning.

With **UserSpy**, you can check whether a username is available on multiple platforms like GitHub, Twitter, Instagram, LinkedIn, and more. The tool can also help in performing basic penetration testing tasks such as brute force attacks and vulnerability scanning.

---

## Features

- **Username Enumeration**: Searches for the existence of a username on multiple platforms (GitHub, Twitter, Instagram, LinkedIn, etc.).
- **Brute Force Attack**: Performs a brute force attack on a given login page (optional).
- **SQL Injection Check**: Detects basic SQL injection vulnerabilities.
- **XSS Detection**: Scans for potential XSS vulnerabilities in URLs.
- **Port Scanning**: Scans open ports on a given host.
- **Proxy Rotation**: Uses rotating proxies to avoid IP bans while making requests.

---

## Requirements

- **Python 3.x** (preferably 3.7+)
- **Required Python libraries**:
    - `aiohttp`
    - `beautifulsoup4`
    - `requests`
    - `fake_useragent`
    - `rich`
    - `IPProxyManager`
    - `sqlite3` (for database support)
    
You can install the required libraries by running:

```bash
pip install aiohttp beautifulsoup4 requests fake_useragent rich
```

---

## Installation

### On Kali Linux / Linux

1. **Clone the repository**:

   Open a terminal in Kali Linux and run:

   ```bash
   git clone https://github.com/renatochuck/UserSpy.git
   cd UserSpy
   ```

2. **Install dependencies**:

   Make sure you have Python 3.x installed. Then, install the required dependencies:

   ```bash
   pip3 install -r requirements.txt
   ```

3. **Run the tool**:

   You can run the tool by executing the following command:

   ```bash
   python3 user_spy.py <username_to_search>
   ```

   **Example**:

   ```bash
   python3 user_spy.py renatochuck
   ```

   This will search for the username `renatochuck` across various platforms and output the results to the console and save them in JSON and CSV formats.

---

### On Windows

1. **Clone the repository**:

   Open Command Prompt or PowerShell and run:

   ```bash
   git clone https://github.com/renatochuck/UserSpy.git
   cd UserSpy
   ```

2. **Install dependencies**:

   Make sure you have Python 3.x installed. Then, install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. **Run the tool**:

   You can run the tool by executing the following command:

   ```bash
   python user_spy.py <username_to_search>
   ```

   **Example**:

   ```bash
   python user_spy.py renatochuck
   ```

   This will search for the username `renatochuck` across various platforms and output the results to the console and save them in JSON and CSV formats.

---

## Usage

### Basic Username Search

To search for a username across multiple platforms:

```bash
python user_spy.py <username>
```

### Enable Brute Force Attack

To enable brute force attack on a login page:

```bash
python user_spy.py <username> --brute-force
```

### Enable SQL Injection Check

To enable SQL injection check:

```bash
python user_spy.py <username> --sql-injection
```

### Enable XSS Detection

To enable XSS detection:

```bash
python user_spy.py <username> --xss
```

### Enable Port Scanning

To enable port scanning on a given host:

```bash
python user_spy.py <username> --port-scan
```

---

## Output

### Console Output

The tool displays the results in a structured table in the terminal/command prompt.

Example:

```
[bold cyan]███████╗ █████╗ ██╗  ██╗ █████╗ ███╗   ██╗██╗
██╔════╝██╔══██╗██║  ██║██╔══██╗████╗  ██║██║
███████╗███████║███████║███████║██╔██╗ ██║██║
╚════██║██╔══██║██╔══██║██╔══██║██║╚██╗██║██║
███████║██║  ██║██║  ██║██║  ██║██║ ╚████║██║
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝[/bold cyan]

🔍 Searching for username: renatochuck

[bold yellow]Platform     | Profile URL                          | Location[/bold yellow]
---------------------------------------------------------
GitHub        | https://github.com/renatochuck        | New York, USA
Twitter       | https://twitter.com/renatochuck       | London, UK
Instagram     | https://www.instagram.com/renatochuck | Paris, France
```

### File Output

The results are saved in both **JSON** and **CSV** formats:

- **JSON**: The results will be saved in `<username>_results.json`.
- **CSV**: The results will be saved in `<username>_results.csv`.

For example, for username `renatochuck`:

- `renatochuck_results.json`
- `renatochuck_results.csv`

---

## Contributing

Feel free to fork the repository and submit pull requests. If you encounter any bugs or have feature requests, open an issue in the GitHub repository.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Disclaimer

This tool is intended for **ethical** security research and educational purposes only. It should not be used for any illegal activities. Ensure you have proper authorization before performing any security testing on websites or services.
```

Now you have a complete `README.md` that includes the description, installation instructions, usage, output examples, and more. Just copy and paste this into your GitHub repository's `README.md` file. Let me know if you need any further adjustments!

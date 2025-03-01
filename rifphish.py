import requests
import re
import json
import tkinter as tk
from ttkthemes import ThemedTk
from tkinter import *
from tkinter import messagebox

# API Keys (Replace with your own)
VIRUSTOTAL_API_KEY = "63cef9a102544bc76c80a65a4aafc542bfb99ce1b6a3702b658bbf0d27cc02a0"
GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSyCbAzER8AWSLgmMmqiF-4WPDOxKbpwTzRI"

# Phishing URL patterns
def is_phishing(url):
    phishing_patterns = [
        r"https?://.*\.ru/.*",
        r"https?://.*\.xyz/.*",
        r"https?://.*\.top/.*",
        r"https?://.*\.info/.*",
        r"https?://.*\.gq/.*",
        r"https?://.*\.cf/.*",
        r"https?://.*\.tk/.*",
        r"^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?/.*",  # IP-based URLs
        r"^https?://.*\.ngrok\.io/.*",  # Ngrok links
        r"^https?://.*\.ml/.*",
        r"^https?://.*\.(ru|xyz|info)/.*",  # Common phishing TLDs
    ]
    return any(re.search(pattern, url) for pattern in phishing_patterns)

# VirusTotal URL Scan
def check_virustotal(url):
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        payload = {"url": url}
        
        # Submit URL for scanning
        response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=payload)
        vt_data = response.json()

        # Get analysis ID
        analysis_id = vt_data.get("data", {}).get("id", "")
        if not analysis_id:
            return "VirusTotal: Unable to scan this URL."

        # Retrieve scan results
        vt_result_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        vt_result_response = requests.get(vt_result_url, headers=headers)
        vt_result_data = vt_result_response.json()
        
        positives = vt_result_data.get("data", {}).get("attributes", {}).get("stats", {}).get("malicious", 0)
        
        if positives > 0:
            return f"⚠️ VirusTotal flagged this URL as malicious ({positives} reports)!"
        return "✅ VirusTotal: This URL appears safe."
    
    except Exception as e:
        return f"VirusTotal API Error: {e}"

# Google Safe Browsing API
def check_google_safe_browsing(url):
    try:
        google_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
        payload = {
            "client": {"clientId": "your_app", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        response = requests.post(google_url, json=payload)
        data = response.json()

        if "matches" in data:
            return "⚠️ Google Safe Browsing flagged this URL as **dangerous**!"
        return "✅ Google Safe Browsing: This URL appears safe."
    
    except Exception as e:
        return f"Google Safe Browsing API Error: {e}"

# Main Scan Function
def scan_url():
    url = url_entry.get().strip()
    
    if not url.startswith(("http://", "https://")):
        messagebox.showwarning("Error", "Invalid URL format. Please include http:// or https://")
        return
    
    # Step 1: Local Phishing Pattern Check
    if is_phishing(url):
        messagebox.showwarning("Warning", "⚠️ This URL matches known phishing patterns!")
        return

    # Step 2: VirusTotal Scan
    vt_result = check_virustotal(url)

    # Step 3: Google Safe Browsing Scan
    gb_result = check_google_safe_browsing(url)

    # Show results in a message box
    messagebox.showinfo("Scan Results", f"{vt_result}\n\n{gb_result}")

# # Create UI
# root = Tk()
# root.title("Phishing Link Scanner")
# root.geometry("450x300")
# root.configure(bg='#1e1e1e')  # Dark theme background

# Label(root, text="Enter URL:", bg='#1e1e1e', fg='white', font=("Arial", 14)).pack(pady=10)
# url_entry = Entry(root, width=50)
# url_entry.pack(pady=5)

# scan_button = Button(root, text="Scan", command=scan_url, bg='red', fg='white', font=("Arial", 14, "bold"))
# scan_button.pack(pady=20)

# root.mainloop()


# Create UI with ThemedTk for styling
root = tk.Tk()
root.title("Phishing Link Scanner -by MOHAMED RIFKAN")
root.geometry("450x300")
root.configure(bg='#1e1e1e')  # Dark theme background


# Add a transparent effect (if your OS supports it)
root.attributes('-transparentcolor', '#F200FF')  # Set transparent background color for OS support


# Customize the title label for an 'electro' feel
title_label = tk.Label(root, text="Enter URL to Scan:", bg='#1e1e1e', fg='lime', font=("Consolas", 16, "bold"))
title_label.pack(pady=15)

# Add the URL input field
url_entry = tk.Entry(root, width=45, font=("Consolas", 12), fg='#00E1FF', bg='black', insertbackground='lime')
url_entry.pack(pady=10)

# Add the Scan button with an 'electro' look
scan_button = tk.Button(root, text="Scan", command=scan_url, bg='red', fg='black', font=("Consolas", 14, "bold"))
scan_button.pack(pady=20)

# Run the UI
root.mainloop()

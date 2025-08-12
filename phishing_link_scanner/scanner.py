import re
import requests
import tldextract
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Function to check for phishing patterns
def check_phishing_patterns(url):
    suspicious_signals = []

    # Check for IP address in URL
    if re.match(r"^(http[s]?:\/\/)?(\d{1,3}\.){3}\d{1,3}", url):
        suspicious_signals.append("URL contains an IP address instead of domain.")

    # Check for @ symbol
    if "@" in url:
        suspicious_signals.append("URL contains '@' symbol.")

    # Check for suspicious keywords
    keywords = ["login", "verify", "update", "secure", "account", "bank", "free"]
    if any(keyword in url.lower() for keyword in keywords):
        suspicious_signals.append("URL contains phishing-related keywords.")

    # Check domain TLD
    extracted = tldextract.extract(url)
    tld = extracted.suffix
    bad_tlds = ["xyz", "top", "gq", "tk", "ml"]
    if tld in bad_tlds:
        suspicious_signals.append(f"Domain uses suspicious TLD: .{tld}")

    return suspicious_signals

# Function to check with VirusTotal API (requires API key)
def check_with_virustotal(url, api_key):
    vt_url = "https://www.virustotal.com/api/v3/urls"
    encoded_url = requests.post(vt_url, headers={
        "x-apikey": api_key
    }, data={"url": url}).json()

    try:
        analysis_id = encoded_url["data"]["id"]
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        result = requests.get(analysis_url, headers={
            "x-apikey": api_key
        }).json()
        return result
    except:
        return None

# Main Program
if __name__ == "__main__":
    url = input("Enter the URL to scan: ").strip()

    print(Fore.YELLOW + "\n[+] Checking for phishing patterns...")
    patterns = check_phishing_patterns(url)

    if patterns:
        print(Fore.RED + "[!] Suspicious patterns found:")
        for p in patterns:
            print(Fore.RED + f" - {p}")
    else:
        print(Fore.GREEN + "[+] No suspicious patterns detected.")

    # Optional: VirusTotal check
    use_vt = input("\nDo you want to check with VirusTotal API? (y/n): ").lower()
    if use_vt == "y":
        api_key = input("Enter your VirusTotal API key: ").strip()
        vt_result = check_with_virustotal(url, api_key)
        if vt_result:
            print(Fore.CYAN + "[+] VirusTotal analysis result fetched.")
            print(vt_result)
        else:
            print(Fore.RED + "[!] Could not fetch data from VirusTotal.")

import requests

def get_subdomains(domain):
    file = open("top100subdomains.txt")
    content = file.read()
    subdomains = content.splitlines()
    discovered_subdomains = []

    for subdomain in subdomains:
        url = f"http://{subdomain}.{domain}"
        try:
            requests.get(url)
        except requests.ConnectionError:
            pass
        else:
            print("[+] Detect subdomain: ", url)
            discovered_subdomains.append(url)
    return discovered_subdomains

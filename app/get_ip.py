import socket

def get_ip_by_hostname(url):
    try:
        return socket.gethostbyname(url)
    except socket.gaierror as error:
        return f'Invalid URL - {error}'

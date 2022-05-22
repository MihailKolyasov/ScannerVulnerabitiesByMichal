#!/usr/bin/env python

from itertools import tee
import sys
import json
import struct
import subdomains
import get_ip
import ScannerVulnerabilities

try:
    # Python 3.x version
    # Read a message from stdin and decode it.
    def getMessage():
        rawLength = sys.stdin.buffer.read(4)
        if len(rawLength) == 0:
            sys.exit(0)
        messageLength = struct.unpack('@I', rawLength)[0]
        message = sys.stdin.buffer.read(messageLength).decode('utf-8')
        return json.loads(message)

    # Encode a message for transmission,
    # given its content.
    def encodeMessage(messageContent):
        encodedContent = json.dumps(messageContent).encode('utf-8')
        encodedLength = struct.pack('@I', len(encodedContent))
        return {'length': encodedLength, 'content': encodedContent}

    # Send an encoded message to stdout
    def sendMessage(encodedMessage):
        sys.stdout.buffer.write(encodedMessage['length'])
        sys.stdout.buffer.write(encodedMessage['content'])
        sys.stdout.buffer.flush()

    while True:
        receivedMessage = getMessage()
        if receivedMessage != "":
            if receivedMessage == "ping":
                sendMessage(encodeMessage("pong3"))
                continue
            target_links = []
            links_at_risk_xss = []
            links_at_risk_sql = []
            links_at_risk_ssrf = []
            depth = receivedMessage[0]
            code = receivedMessage[2]
            value = receivedMessage[4:]
            if code == "1":
                temp = get_ip.get_ip_by_hostname(value)
                sendMessage(encodeMessage(temp))
            if code == "2":
                subdomains_arr = subdomains.get_subdomains(value)
                if not subdomains_arr:
                    sendMessage(encodeMessage("pong3"))
                else:
                    result = {'subdomains': subdomains_arr}
                    jsonString = json.dumps(result, indent=4)
                    sendMessage(encodeMessage(jsonString))
                    
            if code == "3":
                if not target_links:
                    ScannerVulnerabilities.crawl(value, value, target_links, int(depth))
                ScannerVulnerabilities.run_scanner_xss(target_links, links_at_risk_xss)
                if not links_at_risk_xss:
                    sendMessage(encodeMessage("pong3"))
                else:
                    result = {'urls': links_at_risk_xss}
                    jsonString = json.dumps(result, indent=4)
                    sendMessage(encodeMessage(jsonString))
            
            if code == "4":
                if not target_links:
                    ScannerVulnerabilities.crawl(value, value, target_links, int(depth))
                ScannerVulnerabilities.run_scanner_sql(target_links, links_at_risk_sql)
                if not links_at_risk_sql:
                    sendMessage(encodeMessage("pong3"))
                else:
                    result = {'urls': links_at_risk_sql}
                    jsonString = json.dumps(result, indent=4)
                    sendMessage(encodeMessage(jsonString))

            if code == "5":
                if not target_links:
                    ScannerVulnerabilities.crawl(value, value, target_links, int(depth))
                ScannerVulnerabilities.run_scanner_ssrf(target_links, links_at_risk_ssrf)
                if not links_at_risk_ssrf:
                    sendMessage(encodeMessage("pong3"))
                else:
                    result = {'urls': links_at_risk_ssrf}
                    jsonString = json.dumps(result, indent=4)
                    sendMessage(encodeMessage(jsonString))
            

except AttributeError:
    # Python 2.x version (if sys.stdin.buffer is not defined)
    # Read a message from stdin and decode it.
    def getMessage():
        rawLength = sys.stdin.read(4)
        if len(rawLength) == 0:
            sys.exit(0)
        messageLength = struct.unpack('@I', rawLength)[0]
        message = sys.stdin.read(messageLength)
        return json.loads(message)

    # Encode a message for transmission,
    # given its content.
    def encodeMessage(messageContent):
        encodedContent = json.dumps(messageContent)
        encodedLength = struct.pack('@I', len(encodedContent))
        return {'length': encodedLength, 'content': encodedContent}

    # Send an encoded message to stdout
    def sendMessage(encodedMessage):
        sys.stdout.write(encodedMessage['length'])
        sys.stdout.write(encodedMessage['content'])
        sys.stdout.flush()

    while True:
        receivedMessage = getMessage()
        if receivedMessage == "ping":
            sendMessage(encodeMessage("pong2"))



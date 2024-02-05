from mitmproxy import http
import requests
import time
import json
from collections import OrderedDict
from datetime import datetime
import socket
import re
import base64
syslog_host = "192.168.241.133"
syslog_port = 514
def send_syslog_message(log_data, syslog_host, syslog_port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        log_json = json.dumps(log_data)
        message = "<14>" + log_json
        sock.sendto(message.encode(), (syslog_host, syslog_port))
def encode_content(content):
    encoded_content = base64.b64encode(content.encode('utf-8')).decode('utf-8')
    return encoded_content
def extract_filename(request_body):
    pattern = r'filename="([^"]+)"'
    match = re.search(pattern, request_body)
    if match:
        return match.group(1)
    return "N/A"
def extract_content(input_string):
    pattern = r'Content-Type:.*?$(.*?)^------'
    match = re.search(pattern, input_string, re.MULTILINE | re.DOTALL)
    if match:
        content = match.group(1)
        return content.strip()
    else:
        return None
def is_valid_filename(content_type, request_body):
    content_type = content_type.lower()
    if "form-data" in content_type:
        if "boundary=" in content_type and "filename=" in request_body:
           return True
    return False

def check_file_format_encode(string):
    formats = [".txt", ".WPD", ".ODT", ".php", ".c",".py"]
    lowercase_string = string.lower()
    for format in formats:
        lowercase_format = format.lower()
        if lowercase_format in lowercase_string:
            return True
    return False
def check_file_format_stop(string):
    formats = [".RTF", ".DOC", ".DOCX", ".PDF"]
    lowercase_string = string.lower()
    for format in formats:
        lowercase_format = format.lower()
        if lowercase_format in lowercase_string:
            return True
    return False
    
def request(flow: http.HTTPFlow):
    with open("output.txt", "a", encoding='utf-8') as file:
        if  flow.request.method == "POST":
            content_type = flow.request.headers.get("Content-Type", "")
            request_body = flow.request.get_text()
            if is_valid_filename(content_type, request_body) :
                filename = extract_filename(request_body)
                old_content = extract_content(request_body)
                if filename != "blob" :  
                    matches = [m.start() for m in re.finditer(re.escape(extract_content(request_body)), request_body)]
                    if len(matches) >= 2:
                        second_occurrence_index = matches[1]
                        request_body= request_body[:second_occurrence_index] + encode_content(extract_content(request_body)) + request_body[second_occurrence_index + len(request_body):]
                    else:
                        request_body = request_body.replace(extract_content(request_body),encode_content(extract_content(request_body)))
                    new_content = extract_content(request_body)
                    flow.request.text = request_body
                    log_data = f'{{"url-log": "{flow.request.pretty_host}", "event_type": "alert", "Method": "{flow.request.method}", "Filename": "{filename}", "Old_content": "{old_content}", "New_content": "{new_content}"}}'
                    log_data = json.loads(log_data)
                    send_syslog_message(log_data,syslog_host,syslog_port)

                elif filename != "blob" and check_file_format_stop(filename):
                    matches = [m.start() for m in re.finditer(re.escape(extract_content(request_body)), request_body)]
                    if len(matches) >= 2:
                        second_occurrence_index = matches[1]
                        request_body= request_body[:second_occurrence_index] + encode_content(extract_content(request_body)) + request_body[second_occurrence_index + len(request_body):]
                    else:
                        request_body = request_body.replace(extract_content(request_body),encode_content(extract_content(request_body)))
                    new_content = extract_content(request_body)
                    flow.request.text = request_body
                    # log_data = f'{{"url-log": "{flow.request.pretty_host}", "event_type": "alert", "Method": "{flow.request.method}", "Filename": "{filename}"}}'
                    log_data = f'{{"url-log": "{flow.request.pretty_host}", "event_type": "alert", "Method": "{flow.request.method}", "Filename": "{filename}"}}'
                    file.write("log la:"+ log_data)
                    print(new_content)
                    log_data = json.loads(log_data)
                    send_syslog_message(log_data,syslog_host,syslog_port)
                    file.write("new request la:" + flow.request.get_text())
                    
                            

                            
                        
                            
                        
                    
                       

    # Intercept và in ra phản hồi HTTP
   
   

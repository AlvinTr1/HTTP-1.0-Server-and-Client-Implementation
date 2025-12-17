import socket
import threading
import time
import os
import json
import sys
import signal
import mimetypes
from datetime import datetime

# Constants and globals
UPLOAD_DIR = 'Upload'
VISITORS_FILE = 'visitors.json'
RATE_LIMIT = 100  # Requests per minute before ban
REQUEST_WINDOW = 60  # Seconds

visitors_db = {}  # IP -> (visit_count, last_visit_time)
access_lock = threading.Lock()
banned_addresses = set()
request_history = {}  # IP -> list of request timestamps

def initialize_directories():
    if not os.path.exists(UPLOAD_DIR):
        os.makedirs(UPLOAD_DIR)

def load_visitor_data():
    if os.path.exists(VISITORS_FILE):
        with open(VISITORS_FILE, 'r') as f:
            global visitors_db
            visitors_db = json.load(f)

def save_visitor_data():
    with open(VISITORS_FILE, 'w') as f:
        json.dump(visitors_db, f)

def handle_shutdown(signal_num, frame):
    save_visitor_data()
    print("Server shutting down gracefully.")
    sys.exit(0)

def update_visitor_tracking(ip_addr):
    with access_lock:
        if ip_addr in visitors_db:
            visit_count, last_time = visitors_db[ip_addr]
            visit_count += 1
        else:
            visit_count = 1
            last_time = None
        last_time = datetime.now().isoformat()
        visitors_db[ip_addr] = (visit_count, last_time)
    return visit_count, last_time

def handle_get(client_conn, file_target, body_data, visit_count, last_time):
    if not os.path.exists(file_target) or not os.path.isfile(file_target):
        return "404 Not Found", [], b""
    with open(file_target, 'rb') as f:
        body = f.read()
    content_type, _ = mimetypes.guess_type(file_target)
    content_type = content_type or 'application/octet-stream'
    headers = [
        f"Content-Type: {content_type}",
        f"Content-Length: {len(body)}",
        f"Set-Cookie: visit_count={visit_count}",
        f"Set-Cookie: last_visit={last_time}"
    ]
    return "200 OK", headers, body

def handle_head(client_conn, file_target, body_data, visit_count, last_time):
    if not os.path.exists(file_target) or not os.path.isfile(file_target):
        return "404 Not Found", [], b""
    file_size = os.path.getsize(file_target)
    content_type, _ = mimetypes.guess_type(file_target)
    content_type = content_type or 'application/octet-stream'
    headers = [
        f"Content-Type: {content_type}",
        f"Content-Length: {file_size}",
        f"Set-Cookie: visit_count={visit_count}",
        f"Set-Cookie: last_visit={last_time}"
    ]
    return "200 OK", headers, b""

def handle_post(client_conn, file_target, body_data, visit_count, last_time):
    if os.path.exists(file_target):
        return "403 Forbidden", [], b""
    with open(file_target, 'wb') as f:
        f.write(body_data)
    headers = [
        f"Set-Cookie: visit_count={visit_count}",
        f"Set-Cookie: last_visit={last_time}"
    ]
    return "201 Created", headers, b""

def handle_put(client_conn, file_target, body_data, visit_count, last_time):
    status = "200 OK" if os.path.exists(file_target) else "201 Created"
    with open(file_target, 'wb') as f:
        f.write(body_data)
    headers = [
        f"Set-Cookie: visit_count={visit_count}",
        f"Set-Cookie: last_visit={last_time}"
    ]
    return status, headers, b""

def process_client_connection(client_conn, client_addr):
    ip_addr = client_addr[0]
    curr_timestamp = time.time()

    # Update request history and check for DoS
    with access_lock:
        if ip_addr not in request_history:
            request_history[ip_addr] = []
        request_history[ip_addr].append(curr_timestamp)
        # Remove timestamps older than 1 minute
        request_history[ip_addr] = [ts for ts in request_history[ip_addr] if curr_timestamp - ts < REQUEST_WINDOW]
        if len(request_history[ip_addr]) > RATE_LIMIT:
            banned_addresses.add(ip_addr)
            request_history.pop(ip_addr, None)

    if ip_addr in banned_addresses:
        client_conn.send(b"HTTP/1.0 403 Forbidden\r\n\r\nIP banned due to excessive requests.")
        client_conn.close()
        return

    # Receive full request data
    raw_data = b''
    while True:
        chunk = client_conn.recv(4096)
        if not chunk:
            break
        raw_data += chunk
        if b'\r\n\r\n' in raw_data:
            break  # Header complete, but may need more for body

    try:
        # Parse request
        request_str = raw_data.decode('utf-8')
        request_lines = request_str.split('\r\n')
        if not request_lines:
            raise ValueError("Empty request")
        method, target_path, http_ver = request_lines[0].split()
        if http_ver != 'HTTP/1.0':
            raise ValueError("Unsupported version")

        header_dict = {}
        body_index = raw_data.find(b'\r\n\r\n') + 4
        for line in request_lines[1:]:
            if not line:
                break
            key, val = line.split(':', 1)
            header_dict[key.strip()] = val.strip()

        body_data = raw_data[body_index:]
        expected_length = int(header_dict.get('Content-Length', 0))
        while len(body_data) < expected_length:
            body_data += client_conn.recv(expected_length - len(body_data))

        # Prevent path traversal
        if '..' in target_path or not target_path.startswith('/'):
            raise ValueError("Invalid path")

        file_target = os.path.join(UPLOAD_DIR, target_path.lstrip('/'))

        # Update visitor tracking
        visit_count, last_time = update_visitor_tracking(ip_addr)

        # Dispatch to method handler
        handlers = {
            'GET': handle_get,
            'HEAD': handle_head,
            'POST': handle_post,
            'PUT': handle_put
        }
        if method not in handlers:
            raise ValueError("Unsupported method")

        status, response_headers, response_body = handlers[method](client_conn, file_target, body_data, visit_count, last_time)

        # Build response
        response = f"HTTP/1.0 {status}\r\n" + "\r\n".join(response_headers) + "\r\n\r\n"
        client_conn.send(response.encode('utf-8'))
        if method != 'HEAD' and status.startswith('2'):
            client_conn.send(response_body)

    except ValueError as ve:
        client_conn.send(b"HTTP/1.0 400 Bad Request\r\n\r\n")
    except PermissionError:
        client_conn.send(b"HTTP/1.0 403 Forbidden\r\n\r\n")
    except Exception as e:
        print(f"Error handling request: {e}")
        client_conn.send(b"HTTP/1.0 500 Internal Server Error\r\n\r\n")
    finally:
        client_conn.close()

def start_server():
    if len(sys.argv) != 2:
        print("Usage: python server.py <port>")
        sys.exit(1)

    port_num = int(sys.argv[1])
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(('0.0.0.0', port_num))
    server_sock.listen(10)  # Backlog for multiple connections
    print(f"Server started and listening on port {port_num}")

    while True:
        conn, addr = server_sock.accept()
        worker_thread = threading.Thread(target=process_client_connection, args=(conn, addr))
        worker_thread.start()

if __name__ == "__main__":
    initialize_directories()
    load_visitor_data()
    signal.signal(signal.SIGINT, handle_shutdown)
    start_server()
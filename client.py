import socket
import os
import sys
import time

# Constants
DOWNLOAD_DIR = 'Download'

def initialize_directories():
    if not os.path.exists(DOWNLOAD_DIR):
        os.makedirs(DOWNLOAD_DIR)

def send_http_request(host, port, filename, method, is_dos=False):
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect((host, port))

    path = '/' + filename
    body = b''
    if method in ['POST', 'PUT']:
        local_file = os.path.join(DOWNLOAD_DIR, filename)
        if not os.path.exists(local_file):
            print(f"File {filename} not found in {DOWNLOAD_DIR}")
            client_sock.close()
            return
        with open(local_file, 'rb') as f:
            body = f.read()

    request_headers = f"{method} {path} HTTP/1.0\r\nHost: {host}\r\n"
    if body:
        request_headers += f"Content-Length: {len(body)}\r\n"
    request_headers += "\r\n"

    client_sock.send(request_headers.encode('utf-8') + body)

    # Receive response
    response_data = b''
    while True:
        chunk = client_sock.recv(4096)
        if not chunk:
            break
        response_data += chunk

    # Process response
    try:
        response_str = response_data.decode('utf-8', errors='ignore')
        print("Server Response:")
        if method == 'HEAD':
            # Print only headers (up to blank line)
            header_end = response_str.find('\r\n\r\n')
            print(response_str[:header_end])
        else:
            print(response_str)

        if method == 'GET' and '200 OK' in response_str:
            body_start = response_data.find(b'\r\n\r\n') + 4
            body_content = response_data[body_start:]
            with open(os.path.join(DOWNLOAD_DIR, filename), 'wb') as f:
                f.write(body_content)
    except Exception as e:
        print(f"Error processing response: {e}")

    client_sock.close()

def main():
    if len(sys.argv) < 5:
        print("Usage: python client.py <serverHost> <serverPort> <filename> <command> [options]")
        print("Options: -d <number> for DoS mode (sends <number> rapid GET requests)")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    filename = sys.argv[3]
    command = sys.argv[4].upper()

    dos_mode = False
    dos_requests = 0
    if len(sys.argv) > 5 and sys.argv[5] == '-d':
        dos_mode = True
        dos_requests = int(sys.argv[6]) if len(sys.argv) > 6 else 200

    initialize_directories()

    if dos_mode:
        print(f"Sending {dos_requests} rapid GET requests for DoS testing...")
        for _ in range(dos_requests):
            send_http_request(host, port, filename, 'GET')
            time.sleep(0.001)  # Minimal delay for rapid fire
    else:
        if command not in ['GET', 'HEAD', 'POST', 'PUT']:
            print("Invalid command. Must be GET, HEAD, POST, or PUT.")
            sys.exit(1)
        send_http_request(host, port, filename, command)

if __name__ == "__main__":
    main()
import socket
import nmap
from getpass import getpass
import requests
import csv
import os
import hashlib

def port_range():
    while True:
        start_port = input("Enter start port: ")
        try:
            if int(start_port) > 0 and int(start_port) < 66535:
                start_port = int(start_port)
                break
            else:
                print("Start port must be 0-65535.")
        except ValueError:
            print("Invalid input")
    
    while True:
        end_port = input("Enter end port: ")
        try:
            if int(end_port) < start_port:
                print("The end port should be bigger or equal than the start port.")
            elif int(end_port) > 0 and int(end_port) < 66535:
                end_port = int(end_port)
                break
            else:
                print("End port must be 0-65535. ")
        except ValueError:
            print("Invalid input")
    
    return (start_port, end_port)

def scan():
    while True:
        target_host = input("Enter target host: ")
        try:
            target_ip = socket.gethostbyname(target_host)
            break
        except socket.gaierror:
            print("Unable to resolve target, please input a valid host.")
    start_port, end_port = port_range()
    scanner = nmap.PortScanner()
    scanner.scan(target_ip, f"{start_port}-{end_port}", arguments="-Pn")
    print("\nTarget: ", target_ip)
    print("")
    
    print(f"{'PORT':<10}{'STATE':<12}{'SERVICE'}")
    for port in range(start_port, end_port + 1):
        if "tcp" in scanner[target_ip] and port in scanner[target_ip]["tcp"]:
            item = scanner[target_ip]["tcp"][port]
            print(f"{port:<10}{item["state"]:<12}{item["name"]}")
        else:
            print(f"{port:<10}{'closed':<12}{'unknown'}")
    
    print("\n" + "Scan complete.")

def http_scan(base_url, path=None, *headers_to_check):
    errors = set()
    try:
        if path:
            r = requests.get(base_url + "/" + path, timeout=5, allow_redirects=False)
        else:
            r = requests.get(base_url + "/", timeout=5, allow_redirects=False)
        print(f"Requested URL: {r.url}")
        print(f"Status: {r.status_code}")
        print(f"Response Length: {len(r.content)}")
        print(f"Content-Type: {r.headers.get('Content-Type')}")
        for name in headers_to_check:
            if name not in r.headers and f"{name} is not present" not in errors:
                errors.add(f"{name} is not present")
        if errors:
            print("")
            print("Category: Security header")
            print(f"Observation: {', '.join(errors)}")
            print("Review Status: Configuration review")
            print("-" * 80)
        
            return {
                "Requested URL": r.url,
                "Status": r.status_code,
                "Response Length": len(r.content),
                "Content-Type": r.headers.get('Content-Type'),
                "Category": "Security header",
                "Observation": ", ".join(errors),
                "Review Status": "Configuration review"
            }
        else:
            return {
                "Requested URL": r.url,
                "Status": r.status_code,
                "Response Length": len(r.content),
                "Content-Type": r.headers.get('Content-Type'),
                "Category": None,
                "Observation": None,
                "Review Status": None
            }
    except Exception as e:
        print(f"Some errors exsist: {e}")

def test_server_header(base_url, path=None):
    if path:
        response = requests.get(base_url + "/" + path, timeout=5, allow_redirects=False)
    else:
        response = requests.get(base_url + "/", timeout=5, allow_redirects=False)
    if response.headers.get("Server"):
        return {
                "Category": "Server header",
                "Endpoint": base_url,
                "Observation": "Server header present",
                "Review Status": "Informational"
        }
    else:
        return {}

# Server configuration (must match the server)
HOST = "127.0.0.1"
PORT = 12345

# Create TCP socket
client_socket = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

# Connect to the server
client_socket.connect((HOST, PORT))

# Prompt user for username(have to be something not none)
username = ""
password = ""
password_verified = False
otp_verified = False
count = 1
print("Maximum failed attempts: 3\n\n")

while not (password_verified and otp_verified):
    if count > 3:
        print("\nToo many failed attempts.")
        print("Authentication blocked.")
        break

    while not password_verified and count <= 3:

        username = input("Enter your username: ")
        
        if not username:
            print("Username can not be null.")

        password = getpass("Enter your Password: ")
        if not password:
            print("Password can not be null.")

        # Send HELLO command with the valid username
        hello_message = "AUTH|" + username + "|" + hashlib.sha256(password.encode()).hexdigest()

        client_socket.send(
            hello_message.encode()
        )
        # Receive and print server's response
        response = client_socket.recv(1024)
        
        if response.decode() == "OTP_REQUIRED":
            print(f"Attempt {count} → {response.decode()}")
            password_verified = True
        else:
            print(f"Attempt {count} → {response.decode()}")
            count = count + 1

    
    while not otp_verified and count <= 3:
        otp = input("Enter your code: ")
        otp_message = "OTP|" + otp
        
        client_socket.send(
            otp_message.encode()
        )
        
        response = client_socket.recv(1024)
        
        if response.decode() == "ACCESS_GRANTED":
            print(f"Attempt {count} → {response.decode()}")
            otp_verified = True
        else:
            print(f"Attempt {count} → {response.decode()}")
            count = count + 1


# Main loop for operation
while True and otp_verified and password_verified:     
    selection = input(
    """
    Please select a number:
    1. Port scanner
    2. HTTP checker
    3. PCAP Analyzer
    4. Exit
    
    Your selection: 
    """
    )
    
    if selection == "1":
        scan()
        
    elif selection == "2":
        while True:
            target_host = input("Enter target host: ")
            try:
                target_ip = socket.gethostbyname(target_host)
                break
            except socket.gaierror:
                print("Unable to resolve target, please input a valid host.")
        while True:
            port = input("Enter port: ")
            try:
                if int(port) > 0 and int(port) < 66535:
                    port = int(port)
                    break
                else:
                    print("Port must be 0-65535.")
            except ValueError:
                print("Invalid input")
        
        base_url = f"http://{target_ip}:{port}"
        print(f"Your target: {base_url}")
        http_records = []

    
        while True:
            endpoint = input("Enter the endpoint you want to check(Enter 0 if you want to quit): ")
            if endpoint == "0":
                break
            try:
                http_records.append(http_scan(base_url, endpoint, "Content-Security-Policy", "X-Content-Type-Options"))
            except:
                print("Invalid endpoint")
            
        
        with open("http_scan_results.csv", "w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=http_records[0].keys())
            writer.writeheader()
            writer.writerows(http_records)
                    
    elif selection == "3":
        while True:
            file_path = input(
                "Please provide the pcap file (exit to back): "
            )
            ext = os.path.splitext(file_path)[1]
            if ext.lower() != ".pcap":
                print("Invalid pcap format")
                continue
            elif file_path.lower() == "exit":
                break
            else:
                pcap_message = "PCAP|" + file_path
                client_socket.send(
                    pcap_message.encode()
                )
                    
                response = client_socket.recv(1024)
                print(response.decode())
   
                break
                
    
    elif selection == "4":
        client_socket.send(
                "EXIT|".encode()
            )

        response = client_socket.recv(1024)

        print("Server:", response.decode())
        
        break
    
    else:
        print("Please enter a valid number.")
    

# Close socket connection
client_socket.close()
print("Disconnected")

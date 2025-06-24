# Real-Time Network Sniffer and Port Scan Detector

This project is a Python-based network tool that performs two main functions:
1.  Listens to live network traffic and detects potential TCP port scans in real-time.
2.  Captures all sniffed traffic into a `.pcap` file for later offline analysis with tools like Wireshark or Zeek.

## Setup

1.  **Clone the repository:**
    ```
    git clone 
    ```

2.  **Create a Python virtual environment:**
    

3.  **Install dependencies:**
    ```
    pip install -r requirements.txt
    ```

4.  **Configure the network interface:**
    - Create a file named `.env` in the root of the project.
    - Add the name of the network interface you want to sniff.
    
    ```
    INTERFACE_NAME="Your_Interface_Name_Here"
    ```

## Usage

Run the script with administrative/root privileges:


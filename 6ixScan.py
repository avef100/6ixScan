import subprocess
import datetime
import time
import sys

# Function to execute commands and handle errors
def execute_command(command):
    try:
        subprocess.run(command, shell=True, check=True, stderr=subprocess.PIPE)
        return True, None
    except subprocess.CalledProcessError as e:
        return False, e.stderr.decode("utf-8")

# Function to print colorful progress bar
def print_progress_bar(tool_name, progress):
    bar_length = 30
    block = int(round(bar_length * progress))
    progress_bar = "█" * block + "-" * (bar_length - block)
    print(f"\033[96m{tool_name}:\033[0m [\033[92m{progress_bar}\033[0m] {progress*100:.1f}%")

# Function to write results to file
def write_to_file(content):
    filename = f"6ixScan_{datetime.datetime.now().strftime('%m_%d-%H:%M')}.txt"
    with open(filename, "a") as file:
        file.write(content + "\n")

# Main function
def main():
    if len(sys.argv) != 2:
        print("Usage: python3 6ixScan.py <website>")
        sys.exit(1)

    website = sys.argv[1]
    results = []

    # WHOIS
    print_progress_bar("WHOIS", 0.1)
    success, output = execute_command(f"whois {website}")
    if success:
        results.append("WHOIS information exposed on cloud")
    else:
        results.append("No WHOIS info on cloud")

    time.sleep(3)

    # NSLOOKUP
    print_progress_bar("NSLOOKUP", 0.2)
    success, output = execute_command(f"nslookup {website}")
    if success:
        results.append("Found IP and DNS information")
    else:
        results.append("NSLOOKUP failed")

    time.sleep(3)

    # DNSMAP
    print_progress_bar("DNSMAP", 0.3)
    success, output = execute_command(f"dnsmap {website}")
    if success:
        results.append("Found DNS info with DNSMAP")
    else:
        results.append("No DNS info found with DNSMAP")

    time.sleep(3)

    # NIKTO
    print_progress_bar("NIKTO", 0.4)
    success, output = execute_command(f"nikto -h {website}")
    if success:
        results.extend(output.splitlines())
    else:
        results.append("NIKTO failed")

    time.sleep(3)

    # NMAP
    print_progress_bar("NMAP", 0.5)
    success, output = execute_command(f"nmap --script vuln {website}")
    if success:
        results.extend(output.splitlines())
    else:
        results.append("NMAP failed")

    time.sleep(3)

    # SUBLISTER
    print_progress_bar("SUBLISTER", 0.6)
    success, output = execute_command(f"sublist3r -d {website}")
    if success:
        results.append("Found some good stuff with SUBLISTER")
    else:
        results.append("SUBLISTER failed")

    time.sleep(3)

    # SQLMAP
    print_progress_bar("SQLMAP", 0.7)
    success, output = execute_command(f"sqlmap -u {website} --all")
    if "vulnerable" in output:
        results.append("Found some vulnerabilities with SQLMAP")
    else:
        results.append("Nothing to see here with SQLMAP")

    time.sleep(3)

    # DIRB
    print_progress_bar("DIRB", 0.8)
    success, output = execute_command(f"dirb https://{website} -r")
    if "Vulnerable" in output:
        results.append("Vulnerable directory found with DIRB")

    time.sleep(3)

    # UNISCAN
    print_progress_bar("UNISCAN", 0.9)
    success, output = execute_command(f"uniscan -u https://{website} -qweds")
    if "Vulnerable" in output:
        results.append("Vulnerable site found with UNISCAN")

    time.sleep(3)

    # Write results to file
    write_to_file("\n".join(results))

    # Print scan summary
    if results:
        print(f"\n{len(results)} vulnerabilities found.\nScan successfully completed. HAPPY HACKING!")
    else:
        print("\nScan complete. Happy hunting.")

    print(f"Scan results saved in {filename}")

    # Footer
    print("\n\033[1;92m6ixScan by Avraham Freeman\033[0m")

if __name__ == "__main__":
    main()

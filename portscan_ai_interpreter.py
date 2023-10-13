import nmap3
import openai
import argparse
import requests
from bs4 import BeautifulSoup
from config import openai_api_key  # Import the API key from the configuration file

# Set your OpenAI API key
openai.api_key = openai_api_key  # Use the API key from the configuration file

nmap = nmap3.Nmap()


def perform_nmap_scan(target_host, scan_args):
    # Create an nmap scanner object
    nm = nmap.PortScanner()

    # Perform an Nmap scan with the provided arguments
    scan_output = nm.scan(target_host, arguments=scan_args)

    return scan_output

def interact_with_chatgpt(scan_output):
    # Read the Nmap scan results from the file
    with open("nmap_scan_results.txt", "w") as scan_file:
        scan_file.write(str(scan_output))

    # Use ChatGPT to interpret the scan results
    input_text = f"Nmap scan results:\n{scan_output}"
    
    response = openai.Completion.create(
        engine="text-davinci-002",
        prompt=input_text,
        max_tokens=50,
        temperature=0.7,
    )
    
    return response.choices[0].text

def find_known_vulnerabilities(scan_output):
    # Extract service names from the scan results
    service_names = extract_service_names(scan_output)

    # Search for known vulnerabilities based on service names
    known_vulnerabilities = search_vulnerabilities(service_names)

    return known_vulnerabilities

def extract_service_names(scan_output):
    # Parse the scan output to extract service names (e.g., "ssh," "http")
    # You can modify this part based on the actual format of your Nmap scan results
    service_names = []

    # Example parsing logic (modify as needed)
    lines = scan_output.split('\n')
    for line in lines:
        parts = line.split()
        if len(parts) >= 3:
            service_names.append(parts[2])

    return service_names

def search_vulnerabilities(service_names):
    known_vulnerabilities = []

    # Example URL for searching vulnerabilities
    base_url = "https://vulners.com"
    
    for service_name in service_names:
        # Construct the search URL based on service name
        search_url = f"{base_url}/search?query={service_name}"

        # Send a request to the vulnerability search page
        response = requests.get(search_url)

        if response.status_code == 200:
            # Parse the HTML content to find vulnerabilities
            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract known vulnerabilities (modify as needed)
            # This part depends on the structure of the vulnerability information on the website
            vulnerabilities = soup.find_all("div", class_="vulnerability")

            for vulnerability in vulnerabilities:
                known_vulnerabilities.append(vulnerability.text)

    return known_vulnerabilities

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Perform Nmap scan and interpret results")
    parser.add_argument("target_host", help="Target host to scan")
    parser.add_argument("scan_args", help="Nmap scan arguments")
    args = parser.parse_args()

    # Perform the Nmap scan
    scan_output = perform_nmap_scan(args.target_host, args.scan_args)

    # Save the scan results to a file
    with open("nmap_scan_results.txt", "w") as scan_file:
        scan_file.write(str(scan_output))

    # Interpret the scan results with ChatGPT
    interpretation = interact_with_chatgpt(scan_output)

    # Find known vulnerabilities in the scan results
    vulnerabilities = find_known_vulnerabilities(scan_output)

    # Display the interpretation and known vulnerabilities
    print("ChatGPT Interpretation:")
    print(interpretation)

    print("Known Vulnerabilities:")
    for vulnerability in vulnerabilities:
        print(vulnerability)

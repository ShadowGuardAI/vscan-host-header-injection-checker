import argparse
import requests
import logging
import sys
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description='Detect Host header injection vulnerabilities.')
    parser.add_argument('url', type=str, help='The URL to check for Host header injection.')
    parser.add_argument('-H', '--host', type=str, help='The malicious Host header to inject. Defaults to example.com', default='example.com')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output (debug logging).')
    return parser.parse_args()

def is_valid_url(url):
    """
    Validates if the given URL is properly formatted.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False


def check_host_header_injection(url, malicious_host):
    """
    Checks for Host header injection vulnerability.

    Args:
        url (str): The URL to test.
        malicious_host (str): The malicious Host header to inject.

    Returns:
        bool: True if a vulnerability is likely, False otherwise.
    """
    try:
        # Craft the malicious request
        headers = {'Host': malicious_host}
        logging.debug(f"Sending request to {url} with headers: {headers}")
        response = requests.get(url, headers=headers, allow_redirects=False, timeout=10)

        logging.debug(f"Received response with status code: {response.status_code}")
        logging.debug(f"Response headers: {response.headers}")
        logging.debug(f"Response content: {response.content.decode('utf-8', 'ignore')}")  # Decode response content

        # Analyze the response for signs of Host header injection.
        # Common indicators:
        # 1. The malicious host is reflected in the response body or headers.
        # 2. The server returns an unexpected status code (e.g., 400 Bad Request, 500 Internal Server Error).
        # 3. The server redirects to the malicious host.

        if malicious_host in response.url:
             print(f"Possible Host Header Injection vulnerability found. Redirected to malicious host in URL: {response.url}")
             return True

        if malicious_host in response.headers.get('Location', ''):
            print(f"Possible Host Header Injection vulnerability found. Redirected to malicious host in Location header: {response.headers.get('Location')}")
            return True

        if malicious_host in response.content.decode('utf-8', 'ignore'):
            print(f"Possible Host Header Injection vulnerability found. Malicious host reflected in the response body.")
            return True

        if response.status_code in [400, 500]:
            print(f"Possible Host Header Injection vulnerability found.  Unexpected status code: {response.status_code}. This may indicate an error related to the manipulated Host header.")
            return True
        
        return False

    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed: {e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return False



def main():
    """
    Main function to execute the Host header injection check.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    url = args.url
    malicious_host = args.host

    # Input validation
    if not is_valid_url(url):
        print("Error: Invalid URL provided.")
        sys.exit(1)

    print(f"Checking {url} for Host header injection with malicious host: {malicious_host}")

    try:
        if check_host_header_injection(url, malicious_host):
            print("Possible Host Header Injection vulnerability detected.")
        else:
            print("No Host Header Injection vulnerability detected (or not easily detectable with this simple check).")
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        print(f"An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    """
    Entry point for the script.
    """
    main()

"""
Usage Examples:

1. Basic usage:
   python vscan_host_header.py http://example.com

2. Specify a custom malicious host:
   python vscan_host_header.py http://example.com -H malicious.example.com

3. Enable verbose output for debugging:
   python vscan_host_header.py http://example.com -v

Offensive Tools (Illustrative - use with caution and only on authorized systems):

1.  Demonstration of redirecting to a phishing page:
    Assume you've identified a Host Header injection vulnerability on example.com. You could use it to redirect users to a phishing page under your control. The actual steps to set up the phishing page are beyond the scope of this script, but the command would be similar to:
    python vscan_host_header.py http://example.com -H attacker.com 

   Where attacker.com hosts the phishing page. Note: Actually implementing and using this for phishing is illegal and unethical.  This is for demonstration only.  Only test on systems you are authorized to test.

Important Security Notes:

*   Always obtain explicit permission before testing for vulnerabilities on any system. Unauthorized scanning is illegal and unethical.
*   Host header injection can be a complex vulnerability, and this script provides a basic check.  More sophisticated techniques may be required for thorough testing.
*   Be mindful of the potential impact of your tests.  Manipulating the Host header could disrupt the normal functioning of the target website.
*   Implement proper logging and monitoring on your own systems to detect and prevent unauthorized access attempts.
"""
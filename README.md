# JSpector: A Web Application Security Scanner

## Overview
 JSpector is a powerful web application security scanner designed to identify potential security vulnerabilities in web applications. It is a Python-based tool that uses a combination of static and dynamic analysis techniques to detect sensitive information, such as API keys, credentials, and other security-related issues.

## Key Features
 * Static Analysis: JSpector uses regular expressions to scan web pages, JavaScript files, and other resources for sensitive information.
 * Dynamic Analysis: The tool uses a headless browser to interact with web applications, simulating user behavior to detect potential security issues.
 * Cookie Capture: JSpector can capture cookies from web applications, allowing for more accurate scanning and analysis.
 * Redirected URL Handling: The tool can handle redirected URLs, ensuring that all potential security issues are detected.
 * JavaScript Link Extraction: JSpector can extract JavaScript links from web pages, allowing for further analysis and scanning.

## Supported Features
 * API Key Detection: JSpector can detect API keys from various services, including Google, Amazon, Facebook, and more.
 * Credential Detection: The tool can detect credentials, such as usernames and passwords, in web pages and JavaScript files.
 * Sensitive Information Detection: JSpector can detect sensitive information, such as credit card numbers, social security numbers, and more.
 * Custom Regular Expressions: Users can define custom regular expressions to detect specific security issues.

## Usage
 JSpector is easy to use and can be run from the command line. Simply provide the URL of the web application you want to scan, and the tool will do the rest.
 Example Usage: 
   * python3 jspector.py -i https://example.com
   * python3 jspector.py -i file:///home/kali/Desktop/test.txt
   * python3 jspector.py -uf /home/kali/Desktop/urls.txt
     
## System Requirements
 * Python 3.6 or later
 * pip3 (Python package manager)

## Installation
    sudo apt update && sudo apt full-upgrade -y  
    cd Desktop    
    git clone https://github.com/Vigrahak/JSpector.git
    cd JSpector
    sudo apt-get install --upgrade -y python3-pip python3-requests python3-bs4 python3-urllib3 python3-selenium python3-jsbeautifier python3-lxml
    pip3 install --upgrade requests beautifulsoup4 urllib3 selenium webdriver-manager jsbeautifier lxml argparse --break-system-packages
    python3 jspector.py -h

## Troubleshooting and Support
 * Ensure you have the latest version of pip3 and Python3 installed
 * Refer to the documentation and online resources for additional support

## Licensing and Disclaimer
 JSpector is released under the Apache License Version 2.0. See the LICENSE file for more information.

## Contributions and Feedback
 Contributions are welcome! If you'd like to contribute to JSpector, please fork the repository and submit a pull request. Your feedback and suggestions are also appreciated and will help shape the future development of this tool.

## Disclaimer
 JSpector is a tool designed for security research and penetration testing purposes only. Use it responsibly and in accordance with applicable laws and regulations.

## Contact
 vigrahak1828@gmail.com

## Donation
 https://www.paypal.com/paypalme/SourabhS1828

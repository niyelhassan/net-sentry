import nmap
import openai
import os
import json
import argparse
import time
import socket
import sys
from datetime import datetime

# Load API key from environment variable for better security
API_KEY = os.environ.get("OPENAI_API_KEY")
if not API_KEY:
    print("[!] Warning: OPENAI_API_KEY environment variable not set.")
    print("[!] Please set your OpenAI API key with: export OPENAI_API_KEY='your-key-here'")
    print("[!] Continuing without report generation capability.")

# Common ports and their services for reference
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 
    110: "POP3", 111: "RPC", 135: "RPC", 139: "NetBIOS", 143: "IMAP", 
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1723: "PPTP", 
    3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-ALT"
}

# Common vulnerability patterns
VULNERABILITY_PATTERNS = {
    "default_creds": ["admin", "root", "administrator", "default", "password"],
    "dangerous_services": ["telnet", "ftp", "rsh", "rlogin"],
    "outdated_versions": {
        "ssh": ["1.", "2.0", "4.3", "5.3", "6.6", "7.2"],
        "apache": ["1.", "2.0", "2.2."],
        "nginx": ["1.0", "1.1", "1.2", "1.3"]
    }
}

def scan_network(target_ip, scan_type="basic", ports=None):
    """
    Performs a network scan on the target IP address with various levels of detail.
    
    Args:
        target_ip (str): The IP address or hostname to scan
        scan_type (str): Type of scan - "basic", "comprehensive", "vuln", "stealth"
        ports (str): Port specification (e.g., "1-1000" or "21,22,80,443")
        
    Returns:
        dict: Dictionary containing scan results or None if scan fails
    """
    print(f"[*] Scanning target: {target_ip}...")
    print(f"[*] Scan type: {scan_type}")
    start_time = time.time()
    
    nm = nmap.PortScanner()
    try:
        scan_args = ""
        
        if scan_type == "basic":
            scan_args = "-T4 -F"  # Fast scan of top 100 ports
        elif scan_type == "comprehensive":
            scan_args = "-T4 -p- -A"  # Full port range with service detection
        elif scan_type == "vuln":
            scan_args = "-T4 -sV --script vuln"  # Vulnerability scanning
        elif scan_type == "stealth":
            scan_args = "-T2 -sS -Pn"  # Stealthy SYN scan
        else:
            scan_args = "-T4 -F"  # Default to basic
            
        # Add custom port specification if provided
        if ports:
            scan_args += f" -p {ports}"
        
        print(f"[*] Running Nmap with arguments: {scan_args}")
        nm.scan(hosts=target_ip, arguments=scan_args)

        if target_ip not in nm.all_hosts():
            print(f"[-] Target {target_ip} not responding or scan failed.")
            return None

        scan_results = nm[target_ip]
        
        # Enhance scan results with additional metadata
        scan_results['_meta'] = {
            'scan_type': scan_type,
            'scan_args': scan_args,
            'timestamp': datetime.now().isoformat(),
            'scan_duration': time.time() - start_time
        }
        
        # Try to resolve hostname if it's an IP
        try:
            hostname = socket.gethostbyaddr(target_ip)[0]
            scan_results['_meta']['hostname'] = hostname
        except:
            scan_results['_meta']['hostname'] = "Unknown"
        
        # Perform additional vulnerability assessment
        if 'tcp' in scan_results:
            scan_results['_vulnerability_assessment'] = analyze_vulnerabilities(scan_results)
        
        print(f"[+] Scan complete for {target_ip}.")
        print(f"[+] Scan duration: {scan_results['_meta']['scan_duration']:.2f} seconds")
        
        return scan_results
    except nmap.PortScannerError as e:
        print(f"[!] Nmap scan error: {e}")
        return None
    except Exception as e:
        print(f"[!] An unexpected error occurred during scan: {e}")
        return None

def analyze_vulnerabilities(scan_results):
    """
    Analyzes the scan results to identify potential vulnerabilities.
    
    Args:
        scan_results (dict): Nmap scan results
        
    Returns:
        dict: Dictionary of potential vulnerabilities
    """
    vulnerabilities = {
        "open_ports": [],
        "risky_services": [],
        "unusual_ports": [],
        "potential_vulnerabilities": [],
        "risk_score": 0
    }
    
    if 'tcp' not in scan_results:
        return vulnerabilities
    
    open_ports = scan_results['tcp']
    risk_score = 0
    
    for port, info in open_ports.items():
        port = int(port)
        
        # Check if port is open
        if info['state'] == 'open':
            service_info = {
                'port': port,
                'service': info.get('name', 'unknown'),
                'product': info.get('product', 'unknown'),
                'version': info.get('version', 'unknown'),
            }
            vulnerabilities["open_ports"].append(service_info)
            
            # Risk assessment based on port
            if port in COMMON_PORTS:
                risk_score += 1
            else:
                vulnerabilities["unusual_ports"].append(port)
                risk_score += 2  # Unusual ports might indicate backdoors
            
            # Assess risky services
            service = info.get('name', '').lower()
            product = info.get('product', '').lower()
            version = info.get('version', '')
            
            # Check for dangerous services
            for dangerous in VULNERABILITY_PATTERNS["dangerous_services"]:
                if dangerous in service:
                    vulnerabilities["risky_services"].append({
                        'port': port,
                        'service': service,
                        'reason': f"Potentially insecure {service} service"
                    })
                    risk_score += 5
            
            # Check for outdated versions
            for service_key, old_versions in VULNERABILITY_PATTERNS["outdated_versions"].items():
                if service_key in service or service_key in product:
                    for old_ver in old_versions:
                        if version and old_ver in version:
                            vulnerabilities["potential_vulnerabilities"].append({
                                'port': port,
                                'service': service,
                                'version': version,
                                'reason': f"Potentially outdated {service} version: {version}"
                            })
                            risk_score += 7
            
            # Additional specific checks
            if service == 'http' or service == 'https':
                vulnerabilities["potential_vulnerabilities"].append({
                    'port': port,
                    'service': service,
                    'reason': "Web servers should be assessed with specialized web scanners"
                })
                risk_score += 2
                
            elif service == 'ssh' and port != 22:
                vulnerabilities["potential_vulnerabilities"].append({
                    'port': port,
                    'service': service,
                    'reason': "SSH on non-standard port - could be security by obscurity or shadow IT"
                })
                risk_score += 3
    
    # Normalize risk score from 0-100
    total_open_ports = len(vulnerabilities["open_ports"])
    risk_score = min(100, risk_score + (total_open_ports * 2))
    vulnerabilities["risk_score"] = risk_score
    vulnerabilities["risk_level"] = get_risk_level(risk_score)
    
    return vulnerabilities

def get_risk_level(score):
    """Convert numerical risk score to categorical risk level"""
    if score < 10:
        return "Very Low"
    elif score < 30:
        return "Low"
    elif score < 60:
        return "Medium" 
    elif score < 85:
        return "High"
    else:
        return "Critical"

def generate_report(scan_data, target_ip):
    """
    Uses OpenAI API to generate a comprehensive security report based on scan data.
    
    Args:
        scan_data (dict): Nmap scan results enhanced with vulnerability assessment
        target_ip (str): The IP address that was scanned
        
    Returns:
        str: A comprehensive security report
    """
    if not scan_data:
        return "No scan data available to generate report."

    print("[*] Generating comprehensive security report using OpenAI...")

    # Prepare data for the prompt
    open_ports = []
    if 'tcp' in scan_data:
        open_ports = [f"{port} ({scan_data['tcp'][port].get('name', 'unknown')}/{scan_data['tcp'][port].get('state', 'unknown')})" 
                    for port in scan_data['tcp']]

    # Extract OS detection info if available
    os_info = "Not detected"
    if 'osmatch' in scan_data and scan_data['osmatch']:
        os_matches = scan_data['osmatch']
        if len(os_matches) > 0:
            best_match = os_matches[0]
            os_info = f"{best_match.get('name', 'Unknown')} (Accuracy: {best_match.get('accuracy', 'unknown')}%)"

    # Extract vulnerability assessment
    vuln_assessment = scan_data.get('_vulnerability_assessment', {})
    risk_score = vuln_assessment.get('risk_score', 0)
    risk_level = vuln_assessment.get('risk_level', 'Unknown')
    risky_services = vuln_assessment.get('risky_services', [])
    potential_vulns = vuln_assessment.get('potential_vulnerabilities', [])

    # Create a comprehensive prompt for the AI
    prompt = f"""
Analyze the following detailed Nmap scan results for the target IP address {target_ip} and provide a comprehensive security assessment.

## SCAN OVERVIEW
Target IP: {target_ip}
Hostname: {scan_data.get('_meta', {}).get('hostname', 'Unknown')}
Scan Type: {scan_data.get('_meta', {}).get('scan_type', 'basic')}
Scan Command: nmap {scan_data.get('_meta', {}).get('scan_args', '')} {target_ip}
Detected Host Status: {scan_data.get('status', {}).get('state', 'unknown')}
Detected OS: {os_info}
Risk Assessment Score: {risk_score}/100 ({risk_level} Risk)
Open TCP Ports: {open_ports if open_ports else 'None detected'}

## DETAILED PORT & SERVICE INFORMATION
{json.dumps(scan_data.get('tcp', {}), indent=2)}

## VULNERABILITY ASSESSMENT
Risky Services: {json.dumps(risky_services, indent=2) if risky_services else 'None identified'}
Potential Vulnerabilities: {json.dumps(potential_vulns, indent=2) if potential_vulns else 'None identified'}

Please provide a COMPREHENSIVE security report with:
1. Executive Summary: Brief overview of findings and overall security posture
2. Technical Analysis: Detailed breakdown of each open port, service, and potential security implications
3. Vulnerabilities Assessment: Analysis of identified and potential vulnerabilities
4. Attack Surface Analysis: How an attacker might leverage the discovered services
5. Specific Security Recommendations: Concrete actions to mitigate risks
6. Prioritized Remediation Plan: What to address first based on risk

Make the report detailed but accessible to security professionals. Focus on actionable intelligence.
"""

    try:
        # Pass the API key directly to the client constructor
        client = openai.OpenAI(api_key=API_KEY)
        response = client.chat.completions.create(
            model="gpt-4",  # Using a more capable model for detailed security analysis
            messages=[
                {"role": "system", "content": "You are an expert cybersecurity analyst specializing in network security assessment and penetration testing. Provide detailed, actionable security intelligence."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,  # Lower temperature for more consistent, precise responses
            max_tokens=2500   # Allow for longer, more comprehensive responses
        )
        report = response.choices[0].message.content
        print("[+] Comprehensive security report generated successfully.")
        return report
    except openai.APIError as e:
        print(f"[!] OpenAI API Error: {e}")
        return f"Error generating report: {e}"
    except Exception as e:
        print(f"[!] An unexpected error occurred during report generation: {e}")
        return f"Error generating report: {e}"

def save_report(report, target_ip, format="txt"):
    """
    Saves the generated report to a file.
    
    Args:
        report (str): The generated report content
        target_ip (str): The scanned IP address
        format (str): Output format (txt, html, json)
        
    Returns:
        str: Path to the saved report
    """
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"security_report_{target_ip.replace('.', '_')}_{timestamp}.{format}"
    
    try:
        with open(filename, 'w') as f:
            f.write(report)
        print(f"[+] Report saved to {filename}")
        return filename
    except Exception as e:
        print(f"[!] Error saving report: {e}")
        return None

def parse_arguments():
    """
    Parse command line arguments for the script.
    
    Returns:
        argparse.Namespace: Parsed command line arguments
    """
    parser = argparse.ArgumentParser(description="Network Security Scanner and Reporter")
    parser.add_argument("-t", "--target", default="127.0.0.1", 
                        help="Target IP address or hostname (default: 127.0.0.1)")
    parser.add_argument("-s", "--scan-type", choices=["basic", "comprehensive", "vuln", "stealth"],
                        default="basic", help="Type of scan to perform (default: basic)")
    parser.add_argument("-p", "--ports", help="Port specification (e.g., '1-1000' or '21,22,80,443')")
    parser.add_argument("-o", "--output", choices=["txt", "html", "json"], default="txt",
                        help="Report output format (default: txt)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--no-report", action="store_true", help="Skip report generation")
    parser.add_argument("--save", action="store_true", help="Save the report to a file")
    
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    
    print("\n" + "="*60)
    print(f"CYBERSECURITY NETWORK SCANNER AND ANALYZER")
    print("="*60 + "\n")
    
    # Check if target is valid
    try:
        socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[!] Error: Could not resolve hostname {args.target}")
        sys.exit(1)
        
    print(f"[*] Starting scan of {args.target} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Perform the scan
    scan_results = scan_network(args.target, args.scan_type, args.ports)

    if scan_results:
        # Print raw scan results if verbose
        if args.verbose:
            print("\n--- Raw Scan Results ---")
            print(json.dumps(scan_results, indent=2))
            print("------------------------\n")

        # Generate the report unless skipped
        if not args.no_report:
            report = generate_report(scan_results, args.target)
            print("\n--- Security Report ---")
            print(report)
            print("-----------------------\n")
            
            # Save the report if requested
            if args.save:
                save_report(report, args.target, args.output)
    else:
        print("[!] Could not generate report due to scan failure or no results.")
    
    print(f"[*] Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
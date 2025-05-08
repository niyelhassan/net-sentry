# NetSentry: Intelligent Network Security Scanner

NetSentry is a Python-based security tool that enhances Nmap scanning with intelligent analysis and reporting capabilities. It helps security professionals identify potential vulnerabilities in network services and provides actionable recommendations.

![NetSentry Banner](docs/banner.png)

## 🔍 Features

- **Multiple Scan Types**: Basic, comprehensive, vulnerability-focused, and stealth scans
- **Intelligent Analysis**: Automatically analyzes open ports, services, and configurations for security issues
- **Risk Scoring System**: Evaluates threats based on port types and service configurations
- **AI-Powered Reports**: Generates detailed security reports using OpenAI
- **Flexible Output**: Export reports in TXT, HTML, or JSON formats
- **Easy to Use**: Simple command-line interface with multiple options

## 📋 Requirements

- Python 3.7+
- Nmap 7.0+ (must be installed on your system)
- OpenAI API key (for report generation)

## 🚀 Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/net-sentry.git
cd net-sentry
```

2. Install required Python packages:

```bash
pip install -r requirements.txt
```

3. Set your OpenAI API key:

```bash
export OPENAI_API_KEY='your-api-key-here'
```

## 💻 Usage

Basic usage:

```bash
python netsentry.py -t 192.168.1.1
```

Advanced options:

```bash
python netsentry.py -t 192.168.1.1 -s comprehensive -p 1-1000 -o html --save
```

### Command-line Arguments

- `-t`, `--target`: Target IP address or hostname (default: 127.0.0.1)
- `-s`, `--scan-type`: Type of scan - basic, comprehensive, vuln, stealth (default: basic)
- `-p`, `--ports`: Port specification (e.g., '1-1000' or '21,22,80,443')
- `-o`, `--output`: Report output format - txt, html, json (default: txt)
- `-v`, `--verbose`: Enable verbose output
- `--no-report`: Skip report generation
- `--save`: Save the report to a file

## 📊 Example Report

NetSentry generates comprehensive security reports that include:

1. Executive Summary
2. Technical Analysis of open ports and services
3. Vulnerability Assessment
4. Attack Surface Analysis
5. Security Recommendations
6. Prioritized Remediation Plan

Example of a report snippet:

```
# SECURITY ASSESSMENT REPORT

## Executive Summary
The target system (192.168.1.1) has 5 open ports, including HTTP (80) and SSH (22).
Overall risk assessment: MEDIUM (Risk Score: 45/100)
...
```

For complete examples, see the [example_reports](example_reports/) directory.

## 🔒 Security Notes

- Always ensure you have permission to scan the target network/system
- Use stealth scans responsibly
- Do not expose your API keys in public repositories

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

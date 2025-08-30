# Vuln-Report-AI: Automated Security Reporting Tool

An automated command-line tool that performs security scans using popular open-source tools (Nmap, Nuclei, and SQLMap) and leverages a local Large Language Model (LLM) to generate a professional, actionable security report

***

### **🚀 Getting Started**

Follow these steps to set up and run the `Vuln-Report-AI` tool on your local machine.

#### **Prerequisites**

* **Python 3.10 or higher**: `python3 --version`
* **A running LLM instance**: You must have a local LLM running and exposed via an API. This project was developed using [LM Studio](https://lmstudio.ai/) with the `mistral-7b-instruct-v0.3` model.
* **Security Tools**: Ensure `nmap`, `nuclei`, and `sqlmap` are installed and available in your system's PATH.

#### **Installation**

1.  Clone the repository:
    ```bash
    git clone [https://github.com/your-username/Vuln-Report-AI.git](https://github.com/your-username/Vuln-Report-AI.git)
    cd Vuln-Report-AI
    ```

2.  Set up the Python virtual environment and install dependencies:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

#### **Configuration**

Edit the `Vuln-Report-AI/config.toml` file to specify your LLM's API endpoint and any other tool-specific settings.

***

### **🛠️ Usage**

Execute the `start.sh` script from the root directory, providing the target IP address as an argument.

```bash
./start.sh <target_ip>
````

**Example:**

```bash
./start.sh 192.168.1.104
```

The script will run the scans, generate a report, and save it to the `reports/` directory with a timestamped filename, such as `security_report_192.168.1.104_2025-08-30_12-00-00.md`.

-----

### **📂 Project Architecture**

The project follows a modular and clean architecture to separate concerns.

  * `start.sh`: The project's entry point. It orchestrates the Python agent and handles command-line arguments.
  * `config.toml`: A single, centralized configuration file for all settings, adhering to the **DRY (Don't Repeat Yourself)** principle.
  * `src/config.py`: Loads and parses the configuration file.
  * `src/llm_client.py`: An independent client responsible for all communication with the LLM API. This separation allows the LLM to be easily swapped out.
  * `src/agent.py`: The core business logic. It orchestrates the security scans, processes the output, and calls the `LLMClient` to generate the final report. This is a clear example of **dependency injection**.
  * `reports/`: Stores all generated Markdown reports.

## 📝 Report Preview

=================

# EXECUTIVE SUMMARY

Several critical and high-severity vulnerabilities have been identified in the scanned environment, primarily affecting the web server running on port 80. The most pressing issues include CVE-2020-1938 (TCP) and CVE-2012-1823 (HTTP). Additionally, SQL injection attempts were unsuccessful but may indicate potential security gaps.

# CRITICAL VULNERABILITIES

## CVE-2020-1938
- **Vulnerability Name**: [CVE-2020-1938](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1938)
- **Affected Component**: TCP
- **Technical Description**: The system is vulnerable to a critical remote code execution (RCE) vulnerability in the `libssh` library. An attacker can exploit this vulnerability by sending specially crafted packets to execute arbitrary commands with root privileges.

## CVE-2012-1823
- **Vulnerability Name**: [CVE-2012-1823](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-1823)
- **Affected Component**: HTTP
- **Technical Description**: The server is vulnerable to a high-severity remote code execution (RCE) vulnerability due to the use of `allow_url_include` and `auto_prepend_file`. An attacker can exploit this vulnerability by including malicious PHP files from an arbitrary URL, resulting in RCE.

# ACTIONABLE RECOMMENDATIONS

1. **Update libssh library**: Upgrade the affected system's `libssh` library to the latest stable version and apply any available patches to mitigate the risk of CVE-2020-1938 exploitation.

2. **Secure PHP configuration**: Disable the `allow_url_include` directive in your PHP configuration file (php.ini) or use a more restrictive setting, such as only allowing local files to be included. Additionally, remove any unnecessary use of `auto_prepend_file`.

# SECURITY GAPS & WEAKNESSES

- **SQL Injection Attempts**: Though unsuccessful in this instance, the SQLMAP scan suggests that there may be potential SQL injection vulnerabilities. It is recommended to review your database code and implement proper input validation to prevent such attacks.

# ATTACK SURFACE

- **Services**: FTP (21/tcp), SSH (22/tcp), Telnet (23/tcp), SMTP (25/tcp), DNS (53/tcp), HTTP (80/tcp), RPC bind (111/tcp), NetBIOS-SSN (139/tcp), Microsoft-DS (445/tcp), Exec (512/tcp), Login (513/tcp), Shell (514/tcp), MySQL (3306/tcp), AJP13 (8009/tcp), Unknown (8180/tcp)
- **Open Ports**: FTP, SSH, Telnet, SMTP, DNS, HTTP, RPC bind, NetBIOS-SSN, Microsoft-DS, Exec, Login, Shell, MySQL, AJP13, Unknown


-----

### **💡 Project Highlights**

  * **Practical Application:** This project automates a common workflow in **Security Operations Center (SOC) analysis** by generating professional reports from raw security scan data.
  * **Software Design:** The architecture demonstrates a clear understanding of software design principles, including **modularity**, **separation of concerns**, and **dependency injection**.
  * **Code Quality:** The refactored `_process_scan_output` method adheres to **clean coding principles** and the **DRY (Don't Repeat Yourself)** principle, ensuring the code is maintainable and easily testable.
  * **AI Integration:** The tool utilizes a local LLM to transform unstructured data into actionable intelligence, highlighting the ability to integrate modern **AI technologies** into a practical solution.

-----

### **License**

This project is licensed under the **MIT License**.


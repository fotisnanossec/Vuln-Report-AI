# Vuln-Report-AI: Automated Security Reporting Tool

An automated command-line tool that performs security scans using popular open-source tools (Nmap, Nuclei, and SQLMap) and leverages a local Large Language Model (LLM) to generate a professional, actionable security report. This project showcases proficiency in security analysis, Python automation, and software architecture.

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

\!(https:

-----

### **💡 Project Highlights**

  * **Practical Application:** This project automates a common workflow in **Security Operations Center (SOC) analysis** by generating professional reports from raw security scan data.
  * **Software Design:** The architecture demonstrates a clear understanding of software design principles, including **modularity**, **separation of concerns**, and **dependency injection**.
  * **Code Quality:** The refactored `_process_scan_output` method adheres to **clean coding principles** and the **DRY (Don't Repeat Yourself)** principle, ensuring the code is maintainable and easily testable.
  * **AI Integration:** The tool utilizes a local LLM to transform unstructured data into actionable intelligence, highlighting the ability to integrate modern **AI technologies** into a practical solution.

-----

### **License**

This project is licensed under the **MIT License**.


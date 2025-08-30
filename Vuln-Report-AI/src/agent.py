import subprocess
import logging
import os
import sys
import re
from datetime import datetime
from config import load_config
from llm_client import LLMClient
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging for the agent
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ScanFailedError(Exception):
    """Custom exception for scan failures."""
    pass

class LLMGenerationError(Exception):
    """Custom exception for LLM generation failures."""
    pass

class SecurityAgent:
    """
    Orchestrates security scans and report generation.
    """
    def __init__(self, config: dict, llm_client: LLMClient, target_ip: str):
        """
        Initializes the agent with a configuration and an LLM client.
        
        Args:
            config (dict): The configuration dictionary.
            llm_client (LLMClient): The client for the LLM API.
            target_ip (str): The IP address of the target.
        """
        self.config = config
        self.llm_client = llm_client
        self.target_ip = target_ip

    def _execute_command(self, command: list) -> str:
        """
        Executes a shell command and captures its output.

        Args:
            command (list): The command and its arguments.

        Returns:
            str: The combined standard output and standard error.
        
        Raises:
            ScanFailedError: If the command returns a non-zero exit code.
        """
        try:
            logging.info(f"Executing command: {' '.join(command)}")
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True,
                encoding='utf-8'
            )
            logging.info("Command executed successfully with return code %d.", result.returncode)
            
            combined_output = result.stdout
            if result.stderr:
                logging.warning("Command Standard Error:\n\n%s", result.stderr)
                combined_output += f"\n\n--- Standard Error ---\n{result.stderr}"

            return combined_output
        except subprocess.CalledProcessError as e:
            logging.error(f"Command failed with exit code {e.returncode}.")
            logging.error(f"Standard Output: {e.stdout}")
            logging.error(f"Standard Error: {e.stderr}")
            raise ScanFailedError(f"Command '{' '.join(command)}' failed.")
        except FileNotFoundError:
            logging.error(f"Command not found. Make sure the tool is installed and in your PATH.")
            raise ScanFailedError(f"Tool not found: {command[0]}")
        except Exception as e:
            logging.error(f"An unexpected error occurred during command execution: {e}")
            raise ScanFailedError(f"Unexpected error: {e}")

    def run_scan(self) -> str:
        """
        Runs all configured security scans concurrently and processes the output.
        
        Returns:
            str: A combined string of all scan results.
        
        Raises:
            ScanFailedError: If any scan command fails.
        """
        logging.info("Starting security scans in parallel...")
        scan_results = {}
        
        # Get commands from config.toml
        sqlmap_cmd = [part.format(target_ip=self.target_ip) for part in self.config['tools']['sqlmap_command']]
        nuclei_cmd = [part.format(target_ip=self.target_ip) for part in self.config['tools']['nuclei_command']]
        nmap_cmd = [part.format(target_ip=self.target_ip) for part in self.config['tools']['nmap_command']]

        commands = {
            'sqlmap': sqlmap_cmd,
            'nuclei': nuclei_cmd,
            'nmap': nmap_cmd
        }
        
        with ThreadPoolExecutor(max_workers=len(commands)) as executor:
            future_to_scan = {executor.submit(self._execute_command, cmd): name for name, cmd in commands.items()}
            
            for future in as_completed(future_to_scan):
                name = future_to_scan[future]
                try:
                    output = future.result()
                    scan_results[name] = output
                except ScanFailedError as e:
                    logging.error(f"Scan for {name} failed: {e}")
                    raise e
                    
        return self._process_scan_output(scan_results)
    
    def _filter_lines(self, output: str, filter_list: list) -> list:
        """
        Helper method to filter lines from a string based on a list of substrings.
        """
        return [line for line in output.split('\n') if all(f not in line for f in filter_list) and line.strip() != ""]

    def _process_scan_output(self, raw_results: dict) -> str:
        """
        Filters and summarizes the raw scan output to create a concise prompt.
        
        Args:
            raw_results (dict): A dictionary containing the raw output from each security tool.
        
        Returns:
            str: A formatted string containing the combined and filtered scan output.
        """
        summary = ""
        
        # Process sqlmap output
        sqlmap_filters = ['[INFO]', '[WARNING]', '[PAYLOAD]']
        sqlmap_lines = self._filter_lines(raw_results['sqlmap'], sqlmap_filters)
        summary += "--- SQLMAP SCAN RESULTS ---\n"
        summary += "\n".join(sqlmap_lines)
        summary += "\n\n"
        
        # Process nuclei output
        nuclei_filters = ['[INF]']
        nuclei_lines = self._filter_lines(raw_results['nuclei'], nuclei_filters)
        summary += "--- NUCLEI SCAN RESULTS ---\n"
        summary += "\n".join(nuclei_lines)
        summary += "\n\n"
        
        # Process nmap output
        nmap_filters = ['Nmap scan report', 'Nmap done']
        nmap_lines = self._filter_lines(raw_results['nmap'], nmap_filters)
        summary += "--- NMAP SCAN RESULTS ---\n"
        summary += "\n".join(nmap_lines)
        
        return summary

    def generate_report(self, raw_data: str):
        """
        Generates a professional report using the LLM.
        
        Args:
            raw_data (str): The raw output from the security scans.
            
        Returns:
            str: The professional report content.
            
        Raises:
            LLMGenerationError: If the LLM API call fails.
        """
        logging.info("Generating professional report with LLM...")
        try:
            prompt = self.config['report']['prompt_template'].format(raw_data=raw_data)
            report_content = self.llm_client.generate_text(prompt)
            if "Error" in report_content:
                raise LLMGenerationError(report_content)
            logging.info("Report generated successfully.")
            return report_content
        except KeyError as e:
            logging.critical(f"Missing configuration key for report generation: {e}")
            raise LLMGenerationError("Missing report configuration.")
        except Exception as e:
            logging.error(f"An unexpected error occurred during report generation: {e}")
            raise LLMGenerationError(f"Unexpected error: {e}")

    def save_report(self, report_content: str):
        """
        Saves the generated report to a file.
        
        Args:
            report_content (str): The content of the report to save.
        """
        try:
            output_dir = self.config['report']['output_dir']
            os.makedirs(output_dir, exist_ok=True)
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            report_path = os.path.join(output_dir, f"security_report_{self.target_ip}_{timestamp}.md")
            
            with open(report_path, 'w') as f:
                f.write(report_content)
            
            logging.info(f"Report saved to: {report_path}")
        except KeyError as e:
            logging.critical(f"Missing configuration key for saving report: {e}")
            exit(1)
        except IOError as e:
            logging.critical(f"Could not write report to file: {e}")
            exit(1)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        logging.critical("Error: Please provide a target IP address as a command-line argument.")
        sys.exit(1)
        
    target_ip = sys.argv[1]
    
    try:
        logging.info("Starting the security agent...")
        
        # Load configuration
        config = load_config()
        
        # Initialize LLM client and agent with dependency injection
        # Pass the model name from the config to the LLMClient constructor
        llm_client = LLMClient(config['llm']['api_url'], config['llm']['model_name'])
        agent = SecurityAgent(config, llm_client, target_ip)
        
        # Run the full workflow
        processed_scan_results = agent.run_scan()
        
        # Check if the scan results are empty
        if not processed_scan_results.strip():
            logging.warning("Scan results were empty. Skipping report generation.")
            sys.exit(0)
            
        professional_report = agent.generate_report(processed_scan_results)
        agent.save_report(professional_report)
        
        logging.info("All operations completed successfully. Check the reports directory for the output.")
        
    except FileNotFoundError:
        logging.critical("Configuration file not found. Please ensure config.toml exists in the correct directory.")
        exit(1)
    except (ScanFailedError, LLMGenerationError) as e:
        logging.critical(f"An operation failed: {e}")
        exit(1)
    except Exception as e:
        logging.critical(f"An unexpected error occurred: {e}")
        exit(1)

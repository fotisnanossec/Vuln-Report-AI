import requests
import json
import logging

class LLMClient:
    """
    Handles communication with the local LLM API.
    """
    def __init__(self, api_url: str, model_name: str):
        """
        Initializes the client with the LLM API endpoint and model name.
        """
        self.api_url = api_url
        self.model_name = model_name

    def generate_text(self, prompt: str):
        """
        Sends a prompt to the LLM and returns the generated text.
        """
        headers = {"Content-Type": "application/json"}
        
        # This payload format is for the /v1/completions endpoint
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "max_tokens": 32768,
            "temperature": 0.7,
        }
        
        try:
            logging.info(f"Sending request to LLM API at {self.api_url} with model {self.model_name}")
            response = requests.post(self.api_url, headers=headers, data=json.dumps(payload), timeout=480)
            response.raise_for_status()  # Raises HTTPError for bad responses
            data = response.json()
            
            # Extract the generated text from the response payload
            if "choices" in data and len(data["choices"]) > 0:
                generated_content = data["choices"][0].get("text", "").strip()
                return generated_content
            else:
                logging.error("LLM API response did not contain expected 'choices' field.")
                return "Error: Could not generate report from LLM. Invalid API response."

        except requests.exceptions.RequestException as e:
            logging.error(f"LLM API request failed: {e}")
            return "Error: Could not generate report from LLM."
        except Exception as e:
            logging.error(f"An unexpected error occurred during LLM API call: {e}")
            return "Error: Could not generate report from LLM."

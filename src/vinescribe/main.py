import os
import sys
import time

from vinescribe.services.gmail import GmailAuthService, GmailMessageService
from vinescribe.services.llm import GeminiService, LLMService
from vinescribe.services.image import resize_image
from vinescribe.models.wine import WineModel
from google.genai import types
from typing import List, Optional
import json
import functools
import logging
from ratelimit import limits, sleep_and_retry
from tenacity import retry, stop_after_attempt, wait_exponential
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VineScribeEmailer:
    """Class to handle email processing for wine database management."""
    
    DEFAULT_CONFIG = types.GenerateContentConfig(
        temperature=1,
        top_p=0.95,
        top_k=40,
        max_output_tokens=8192,
        response_mime_type="text/plain",
    )
    
    MODEL_NAME = "gemini-2.0-flash"
    
    def __init__(self, email_client: GmailMessageService, llm: LLMService):
        """Initialize with email client and LLM service."""
        self.email = email_client
        self.llm = llm
        self._enforce_rate_limit = functools.partial(
            self._rate_limiter,
            calls=self.llm.rate_limit_calls,
            period=self.llm.rate_limit_period,
        )

    @staticmethod
    @sleep_and_retry
    def _rate_limiter(calls, period):
        """Internal method to enforce rate limiting dynamically."""
        limits(calls=calls, period=period)(lambda: None)()
        logger.info("Rate limit check passed. Proceeding with request.")

    def get_messages_with_keyword(
        self, messages: List[dict], keyword: str, search_in: str = "subject"
    ) -> List[dict]:
        """Find messages containing a specific keyword."""
        if search_in != "subject":
            logger.warning("Keywords in fields other than subject are not yet supported")
            return []
            
        matching_messages = []
        for msg in messages:
            message_content = self.email.get_message(msg["id"])
            for header in message_content["payload"]["headers"]:
                if header["name"] == "Subject" and keyword.lower() in str(header["value"]).lower():
                    matching_messages.append(msg)
                    break
        
        return matching_messages

    @retry(
        stop=stop_after_attempt(3), 
        wait=wait_exponential(multiplier=1, min=1, max=10)
    )
    def extract_text_from_attachment(
        self,
        attachment: dict,
        instruction: str,
        config: Optional[types.GenerateContentConfig] = None,
    ) -> str:
        """Extract text information from an image attachment using LLM."""
        config = config or self.DEFAULT_CONFIG
        
        contents = [
            types.Content(
                role="user",
                parts=[
                    types.Part.from_bytes(
                        mime_type=attachment["mimetype"],
                        data=resize_image(attachment["data"]),
                    ),
                    types.Part.from_text(text=instruction),
                ],
            )
        ]

        self._enforce_rate_limit()
        response = self.llm.client.models.generate_content(
            model=self.MODEL_NAME,
            contents=contents,
            config=config,
        )
        return response.text

    @retry(
        stop=stop_after_attempt(3), 
        wait=wait_exponential(multiplier=1, min=1, max=10)
    )
    def convert_page_entry_to_json(self, text_entry: str) -> list:
        """Convert textual wine notes to structured JSON format."""
        self._enforce_rate_limit()

        response = self.llm.client.models.generate_content(
            model=self.MODEL_NAME,
            contents=f"##Notes:##\n\n{text_entry}\n\nGiven the notes above, convert the entries into JSON format.",
            config={
                "response_mime_type": "application/json",
                "response_schema": list[WineModel],
            },
        )
        logger.info("Received response from model. Parsing JSON...")
        result = json.loads(response.text)
        logger.info("Successfully converted text to JSON.")
        return result

    @retry(
        stop=stop_after_attempt(3), 
        wait=wait_exponential(multiplier=1, min=1, max=10)
    )
    def compare_wine_to_database(
        self,
        wine_text: str,
        existing_data: List,
        config: Optional[types.GenerateContentConfig] = None,
    ) -> str:
        """Compare wine details to existing database entries."""
        config = config or self.DEFAULT_CONFIG

        prompt = (
            f"##Notes:##\n\n{wine_text}\n\n"
            f"Given the notes above, compare the wine in the note to the data here:\n{str(existing_data)}. "
            f"If there is a match between the wine in the note to the data, write what the notes were "
            f"and when the entry was made. If not, state that the wine has no entry. "
            f"If there is a similar wine, say which one and why it is similar."
        )

        self._enforce_rate_limit()
        response = self.llm.client.models.generate_content(
            model=self.MODEL_NAME,
            contents=prompt,
            config=config,
        )
        logger.info("Received comparison response from model.")
        return response.text

    @retry(
        stop=stop_after_attempt(3), 
        wait=wait_exponential(multiplier=1, min=1, max=10)
    )
    def compose_email_response(
        self, 
        comparisons: List[str], 
        config: Optional[types.GenerateContentConfig] = None
    ) -> str:
        """Compose a friendly email response summarizing wine comparisons."""
        config = config or self.DEFAULT_CONFIG
        
        prompt = (
            f"##Notes:##\n\n{str(comparisons)}\n\n"
            f"This is a list of comparisons for user queries to see if the wine is in the database. "
            f"Write a response to indicate if this wine has notes in the database or if not, any similar wines. "
            "If there are similar wines, give the tasting notes of those so the user knows if the query wine is one they may like."
            f"Sign off as Best, VineScribe. Only include the response itself. Be friendly and helpful!"
        )

        self._enforce_rate_limit()
        response = self.llm.client.models.generate_content(
            model=self.MODEL_NAME,
            contents=prompt,
            config=config,
        )
        return response.text
    
    def process_page_emails(self, messages: List[dict], existing_data: list, wine_data_path: str) -> None:
        """Process emails with 'page' keyword to add new wine entries."""
        page_matches = self.get_messages_with_keyword(messages, keyword="page")
        
        for msg in page_matches:
            return_address = self.email.get_return_address(msg["id"])
            all_extracted_text = []
            
            attachments = self.email.get_attachments(
                user_id="me", msg_id=msg["id"], mimetype_filter="image"
            )
            
            for attachment in attachments:
                instruction = """Given this image:
                First, describe the image
                Then, detail the notes. Include dates, vintage, manufacturer and notes
                """
                extracted_text = self.extract_text_from_attachment(
                    attachment=attachment, instruction=instruction
                )
                json_data = self.convert_page_entry_to_json(text_entry=extracted_text)

                logger.info("Appending new wine data to database")
                existing_data.append(json_data)
                all_extracted_text.append(extracted_text)

            if all_extracted_text:
                # Save updated data
                with open(wine_data_path, "w") as file:
                    json.dump(existing_data, file, indent=4)
                
                # Create email response
                body = "Extracted entries:\n\n"
                for i, text in enumerate(all_extracted_text):
                    body += f"{i+1}.\n{text}\n\n"
                body += "\n--Petrobyte"
                
                # Send confirmation email
                logger.info(f"Sending confirmation email to {return_address}")
                self.email.send_message(
                    to=return_address,
                    subject="Extracted Page",
                    body=body,
                )
            
            # Mark as read regardless of attachments
            logger.info(f"Marking message {msg['id']} as read")
            self.email.mark_message_as_read(msg["id"])

    def process_check_emails(self, messages: List[dict], existing_data: list) -> None:
        """Process emails with 'check' keyword to look up wines."""
        check_matches = self.get_messages_with_keyword(messages, keyword="check")
        
        for msg in check_matches:
            comparisons = []
            attachments = self.email.get_attachments(
                user_id="me", msg_id=msg["id"], mimetype_filter="image"
            )
            
            for attachment in attachments:
                instruction = """Given this image:
                First, describe the image
                Then, detail the label. Include dates, vintage, manufacturer and varietal
                """
                extracted_text = self.extract_text_from_attachment(
                    attachment=attachment, instruction=instruction
                )
                comparison = self.compare_wine_to_database(
                    wine_text=extracted_text, existing_data=existing_data
                )
                comparisons.append(comparison)

            if comparisons:
                return_address = self.email.get_return_address(msg["id"])
                email_response = self.compose_email_response(comparisons=comparisons)
                
                logger.info(f"Sending wine comparison results to {return_address}")
                self.email.send_message(
                    to=return_address,
                    subject="Did you drink that wine?",
                    body=email_response,
                )
            
            # Mark as read regardless of attachments
            logger.info(f"Marking message {msg['id']} as read")
            self.email.mark_message_as_read(msg["id"])

def load_wine_database(file_path: str) -> list:
    """Load existing wine database or initialize a new one."""
    try:
        with open(file_path, "r") as file:
            data = json.load(file)
            return data if isinstance(data, list) else [data]
    except (FileNotFoundError, json.JSONDecodeError):
        logger.warning(f"Could not load wine database from {file_path}. Starting with empty database.")
        return []

def main():
    # Create a lock file
    if os.path.exists("vinescribe.lock"):
        # Check if lock is stale (older than 30 minutes)
        if time.time() - os.path.getmtime("vinescribe.lock") < 1800:
            print("Another instance is running. Exiting.")
            sys.exit(0)
    
    # Create lock
    with open("vinescribe.lock", "w") as f:
        f.write(str(time.time()))

    try:
        # Configuration
        wine_data_path = "winedb.json"
        
        # Initialize services
        auth = GmailAuthService()
        email = GmailMessageService(auth)
        llm = GeminiService()
        
        # Load existing wine database
        existing_data = load_wine_database(wine_data_path)
        
        # Create emailer instance
        emailer = VineScribeEmailer(email_client=email, llm=llm)
        # Get unread emails
        messages = emailer.email.list_messages(query="label:UNREAD")
        
        if len(messages) < 1:
            logger.info("No unread messages found.")
            return
        
        # Process different types of emails
        emailer.process_page_emails(messages, existing_data, wine_data_path)
        emailer.process_check_emails(messages, existing_data)
    finally:
        #remove lock when done
        if os.path.exists("vinescribe.lock"):
            os.remove("vinescribe.lock")

if __name__ == "__main__":
    main()

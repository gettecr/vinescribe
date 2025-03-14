import os
import time
import base64
import logging
from typing import List, Dict, Optional, Any, Union, Generator
from email.message import EmailMessage
import asyncio
from contextlib import contextmanager

import dotenv
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
from apiclient import errors

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

dotenv.load_dotenv()

SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
GMAIL_AUTH_FILE = os.getenv("GMAIL_AUTH_FILE")
GMAIL_CREDENTIALS_FILE = os.getenv("GMAIL_CREDENTIALS_FILE")
DEFAULT_SENDER_EMAIL = os.getenv("DEFAULT_SENDER_EMAIL")

# Rate limiting constants
MAX_REQUESTS_PER_MINUTE = 60
REQUEST_INTERVAL = 60 / MAX_REQUESTS_PER_MINUTE  # seconds


class GetCredentialsException(Exception):
    """Error raised when an error occurred while retrieving credentials.

    Attributes:
        authorization_url: Authorization URL to redirect the user to in order to
                           request offline access.
    """

    def __init__(self, authorization_url: str, message: str = "Error retrieving credentials"):
        """Construct a GetCredentialsException.
        
        Args:
            authorization_url: The URL for authorization
            message: Error message
        """
        self.authorization_url = authorization_url
        super().__init__(message)

class NoRefreshTokenException(GetCredentialsException):
    """Error raised when no refresh token has been found."""

    def __init__(self, authorization_url: str):
        """Construct a NoRefreshTokenException.
        
        Args:
            authorization_url: The URL for authorization
        """
        super().__init__(authorization_url, "No refresh token found")

class GmailApiError(Exception):
    """Base exception for Gmail API errors."""
    pass


class GmailAuthService:
    """Service to handle Gmail API authentication."""
    
    def __init__(
        self,
        scopes: List[str] = SCOPES,
        token_file: str = GMAIL_AUTH_FILE,
        credential_file: str = GMAIL_CREDENTIALS_FILE,
    ):
        """Initialize the Gmail authentication service.
        
        Args:
            scopes: List of OAuth scopes required
            token_file: Path to the token file
            credential_file: Path to the credentials file
        """
        self.token_file = token_file
        self.credential_file = credential_file
        self.scopes = scopes
        self.creds = self.authorize()

    def authorize(self) -> Credentials:
        """Authorize and obtain credentials.
        
        Returns:
            Valid credentials for Gmail API access
            
        Raises:
            FileNotFoundError: If credential files cannot be found
            NoRefreshTokenException: If no refresh token is available
        """
        creds = None
        try:
            creds = self.from_file()
            logger.info("Loaded credentials from file")
        except FileNotFoundError:
            logger.info("No token file found, initiating OAuth flow")
            creds = self.local_oauth()
            self.save_credentials_to_file(creds)
            logger.info("OAuth flow completed and credentials saved")
            
        if not creds.valid:
            try:
                logger.info("Credentials not valid, refreshing token")
                creds = self.refresh_token(creds)
                self.save_credentials_to_file(creds)
                logger.info("Token refreshed and saved")
            except RefreshError:
                logger.info("Refresh token expired or invalid - need to reauth")
                creds = self.local_oauth()
                self.save_credentials_to_file(creds)
                logger.info("OAuth flow completed and credentials saved")
            
        return creds

    def from_file(self) -> Credentials:
        """Load credentials from a token file.
        
        Returns:
            Credentials object loaded from file
            
        Raises:
            FileNotFoundError: If the token file doesn't exist
        """
        if not self.token_file:
            raise FileNotFoundError("Token file path not specified in environment variables")
            
        if os.path.exists(self.token_file):
            logger.debug(f"Loading credentials from {self.token_file}")
            creds = Credentials.from_authorized_user_file(
                self.token_file, scopes=self.scopes
            )
            return creds
        else:
            raise FileNotFoundError(f"No existing token file found at {self.token_file}")

    def local_oauth(self) -> Credentials:
        """Perform local OAuth flow to get credentials.
        
        Returns:
            Credentials from local OAuth flow
            
        Raises:
            FileNotFoundError: If credentials file is not found
        """
        if not self.credential_file:
            raise FileNotFoundError("Credential file path not specified in environment variables")
            
        if os.path.exists(self.credential_file):
            flow = InstalledAppFlow.from_client_secrets_file(
                self.credential_file, self.scopes
            )
            creds = flow.run_local_server(port=0)
            return creds
        else:
            raise FileNotFoundError(
                f"Credentials file not found at {self.credential_file}. Add file path to .env"
            )

    def refresh_token(self, creds: Credentials) -> Credentials:
        """Refresh the access token if expired.
        
        Args:
            creds: Credentials object to refresh
            
        Returns:
            Refreshed credentials
            
        Raises:
            NoRefreshTokenException: If no refresh token is available
        """
        if not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                logger.debug("Refreshing expired token")
                creds.refresh(Request())    
            elif not creds.refresh_token:
                raise NoRefreshTokenException("https://developers.google.com/gmail/api/auth/scopes")
        return creds

    def save_credentials_to_file(self, creds: Credentials) -> None:
        """Save credentials to token file.
        
        Args:
            creds: Credentials to save
        """
        if not self.token_file:
            logger.warning("Token file path not specified, skipping credential save")
            return
            
        with open(self.token_file, "w") as token:
            token.write(creds.to_json())
            logger.debug(f"Credentials saved to {self.token_file}")

class GmailMessageService:
    """Service to interact with Gmail messages and attachments."""

    def __init__(self, user_auth_service: GmailAuthService):
        """Initialize the Gmail message service.
        
        Args:
            user_auth_service: Authenticated GmailAuthService instance
        """
        self.creds = user_auth_service.creds
        self.service = self.create_service()
        self._last_request_time = 0

    def create_service(self) -> Any:
        """Create a Gmail API client.
        
        Returns:
            Gmail API service object
        """
        return build("gmail", "v1", credentials=self.creds)

    @contextmanager
    def _rate_limit(self) -> Generator[None, None, None]:
        """Context manager to handle rate limiting.
        
        Yields:
            None
        """
        current_time = time.time()
        elapsed = current_time - self._last_request_time
        
        if elapsed < REQUEST_INTERVAL:
            time.sleep(REQUEST_INTERVAL - elapsed)
            
        try:
            yield
        finally:
            self._last_request_time = time.time()

    def send_message(self, to: str, subject: str, body: str, 
                    from_email: Optional[str] = None) -> Dict[str, Any]:
        """Send an email message.
        
        Args:
            to: Recipient email address
            subject: Email subject
            body: Email body content
            from_email: Sender email address (defaults to environment variable)
            
        Returns:
            Response from the API
            
        Raises:
            GmailApiError: If message sending fails
        """
        sender = from_email or DEFAULT_SENDER_EMAIL
        if not sender:
            raise ValueError("Sender email not specified and DEFAULT_SENDER_EMAIL not set in environment")

        try:
            with self._rate_limit():
                message = EmailMessage()
                message.set_content(body)
                message["To"] = to
                message["From"] = sender
                message["Subject"] = subject

                encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
                create_message = {"raw": encoded_message}
                
                send_message = (
                    self.service.users()
                    .messages()
                    .send(userId="me", body=create_message)
                    .execute()
                )
                
                logger.info(f'Message sent successfully, id: {send_message["id"]}')
                return send_message

        except HttpError as error:
            logger.error(f"Failed to send message: {error}")
            raise GmailApiError(f"Failed to send message: {error}")
        
    async def send_message_async(self, to: str, subject: str, body: str, 
                               from_email: Optional[str] = None) -> Dict[str, Any]:
        """Send an email message asynchronously.
        
        Args:
            to: Recipient email address
            subject: Email subject
            body: Email body content
            from_email: Sender email address (defaults to environment variable)
            
        Returns:
            Response from the API
            
        Raises:
            GmailApiError: If message sending fails
        """
        return await asyncio.to_thread(self.send_message, to, subject, body, from_email)

    def list_messages(self, user_id: str = "me", query: str = "label:UNREAD", 
                     max_results: int = 100) -> List[Dict[str, Any]]:
        """List messages matching the specified criteria.
        
        Args:
            user_id: User's email address or 'me'
            query: Gmail search query
            max_results: Maximum number of results to return
            
        Returns:
            List of messages
            
        Raises:
            GmailApiError: If message listing fails
        """
        try:
            with self._rate_limit():
                result = self.service.users().messages().list(
                    userId=user_id, q=query, maxResults=max_results
                ).execute()
                
                messages = result.get('messages', [])
                next_page_token = result.get('nextPageToken')
                
                # Handle pagination
                while next_page_token:
                    with self._rate_limit():
                        result = self.service.users().messages().list(
                            userId=user_id, 
                            q=query, 
                            maxResults=max_results,
                            pageToken=next_page_token
                        ).execute()
                        
                        messages.extend(result.get('messages', []))
                        next_page_token = result.get('nextPageToken')
                        
                        if len(messages) >= max_results:
                            break
                            
                return messages[:max_results]
                
        except HttpError as error:
            logger.error(f"Failed to list messages: {error}")
            raise GmailApiError(f"Failed to list messages: {error}")

    def get_message(self, msg_id: str, user_id: str = "me") -> Dict[str, Any]:
        """Get a message by ID.
        
        Args:
            msg_id: Message ID
            user_id: User's email address or 'me'
            
        Returns:
            Message details
            
        Raises:
            GmailApiError: If message retrieval fails
        """
        try:
            with self._rate_limit():
                return self.service.users().messages().get(
                    userId=user_id, id=msg_id
                ).execute()
        except HttpError as error:
            logger.error(f"Failed to get message {msg_id}: {error}")
            raise GmailApiError(f"Failed to get message {msg_id}: {error}")
        
    def batch_get_messages(self, msg_ids: List[str], user_id: str = "me") -> List[Dict[str, Any]]:
        """Get multiple messages by ID in batch.
        
        Args:
            msg_ids: List of message IDs
            user_id: User's email address or 'me'
            
        Returns:
            List of message details
            
        Raises:
            GmailApiError: If message retrieval fails
        """
        messages = []
        for msg_id in msg_ids:
            try:
                with self._rate_limit():
                    message = self.service.users().messages().get(
                        userId=user_id, id=msg_id
                    ).execute()
                    messages.append(message)
            except HttpError as error:
                logger.warning(f"Failed to get message {msg_id}: {error}")
                # Continue with next message
        return messages
    def mark_message_as_read(self, msg_id: str, user_id: str = "me") -> Dict[str, Any]:
        """Mark a message as read.
        
        Args:
            msg_id: Message ID
            user_id: User's email address or 'me'
            
        Returns:
            Modified message details
            
        Raises:
            GmailApiError: If modification fails
        """
        try:
            with self._rate_limit():
                return self.service.users().messages().modify(
                    userId=user_id, 
                    id=msg_id, 
                    body={"removeLabelIds": ["UNREAD"]}
                ).execute()
        except HttpError as error:
            logger.error(f"Failed to mark message {msg_id} as read: {error}")
            raise GmailApiError(f"Failed to mark message {msg_id} as read: {error}")

    def batch_mark_messages_as_read(self, msg_ids: List[str], user_id: str = "me") -> List[Dict[str, Any]]:
        """Mark multiple messages as read in batch.
        
        Args:
            msg_ids: List of message IDs
            user_id: User's email address or 'me'
            
        Returns:
            List of modified message details
            
        Raises:
            GmailApiError: If batch modification fails
        """
        try:
            with self._rate_limit():
                batch = self.service.new_batch_http_request()
                
                for msg_id in msg_ids:
                    batch.add(
                        self.service.users().messages().modify(
                            userId=user_id,
                            id=msg_id,
                            body={"removeLabelIds": ["UNREAD"]}
                        )
                    )
                    
                batch_results = []
                batch.execute()
                return batch_results
                
        except HttpError as error:
            logger.error(f"Failed to batch mark messages as read: {error}")
            raise GmailApiError(f"Failed to batch mark messages as read: {error}")

    def get_message_attachment(self, msg_id: str, attachment_id: str, 
                             user_id: str = "me") -> Dict[str, Any]:
        """Get a specific attachment from a message.
        
        Args:
            msg_id: Message ID
            attachment_id: Attachment ID
            user_id: User's email address or 'me'
            
        Returns:
            Attachment details
            
        Raises:
            GmailApiError: If attachment retrieval fails
        """
        try:
            with self._rate_limit():
                attachment = self.service.users().messages().attachments().get(
                    userId=user_id,
                    messageId=msg_id,
                    id=attachment_id
                ).execute()
                
                return {
                    "attachment_id": attachment_id,
                    "message_id": msg_id,
                    "data": base64.urlsafe_b64decode(attachment["data"].encode("UTF-8")),
                    "size": attachment["size"]
                }
                
        except HttpError as error:
            logger.error(f"Failed to get attachment {attachment_id} from message {msg_id}: {error}")
            raise GmailApiError(f"Failed to get attachment {attachment_id}: {error}")

    def get_attachments(self, msg_id: str, user_id: str = "me", 
                       mimetype_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get and store attachments from a message.
        
        Args:
            msg_id: Message ID
            user_id: User's email address or 'me'
            mimetype_filter: Filter attachments by MIME type
            
        Returns:
            List of attachment details
            
        Raises:
            GmailApiError: If attachment retrieval fails
        """
        attachments = []
        try:
            message = self.get_message(msg_id=msg_id, user_id=user_id)
            
            # Extract message parts
            parts = self._extract_message_parts(message)
            
            # Process attachments
            for part in parts:
                attachment = self._process_attachment_part(
                    part, message, user_id, mimetype_filter
                )
                if attachment:
                    attachments.append(attachment)
                    
            return attachments
            
        except HttpError as error:
            logger.error(f"Failed to get attachments from message {msg_id}: {error}")
            raise GmailApiError(f"Failed to get attachments: {error}")

    def _extract_message_parts(self, message: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract all parts from a message.
        
        Args:
            message: Message object
            
        Returns:
            List of message parts
        """
        all_parts = []
        parts_queue = [message["payload"]]
        
        while parts_queue:
            current_part = parts_queue.pop(0)
            all_parts.append(current_part)
            
            if current_part.get("parts"):
                parts_queue.extend(current_part["parts"])
                
        return all_parts

    def _process_attachment_part(self, part: Dict[str, Any], message: Dict[str, Any], 
                              user_id: str, mimetype_filter: Optional[str]) -> Optional[Dict[str, Any]]:
        """Process a message part that might contain an attachment.
        
        Args:
            part: Message part
            message: Full message object
            user_id: User's email address or 'me'
            mimetype_filter: Filter for MIME type
            
        Returns:
            Attachment details or None if part is not an attachment or doesn't match filter
        """
        if not part.get("filename"):
            return None
            
        # Check if the part matches the MIME type filter
        if mimetype_filter:
            message_mimetype = part.get("mimeType", "")
            maintype, subtype = message_mimetype.split("/") if "/" in message_mimetype else (message_mimetype, "")
            
            if mimetype_filter not in [message_mimetype, maintype, subtype]:
                return None
        
        # Extract attachment data
        file_data = None
        if "data" in part["body"]:
            file_data = base64.urlsafe_b64decode(part["body"]["data"].encode("UTF-8"))
            logger.debug(f"FileData for {message['id']}, {part['filename']} found in body")
        elif "attachmentId" in part["body"]:
            with self._rate_limit():
                attachment = self.get_message_attachment(
                    msg_id=message["id"],
                    attachment_id=part["body"]["attachmentId"],
                    user_id=user_id
                )
                
                file_data = base64.urlsafe_b64decode(attachment["data"].encode("UTF-8"))
                logger.debug(f"FileData for {message['id']}, {part['filename']} found via attachmentId")
        
        if not file_data:
            return None
            
        return {
            "message_id": message["id"],
            "filename": part["filename"],
            "mimetype": part.get("mimeType", ""),
            "data": file_data,
            "size": part.get("size") or len(file_data)
        }

    def get_return_address(self, msg_id: str, user_id: str = "me") -> str:
        """Get the return address from a message.
        
        Args:
            msg_id: Message ID
            user_id: User's email address or 'me'
            
        Returns:
            Return email address
            
        Raises:
            GmailApiError: If message retrieval fails
            ValueError: If no return address is found
        """
        try:
            message = self.get_message(msg_id=msg_id, user_id=user_id)
            
            # First look for Return-Path header
            for header in message["payload"]["headers"]:
                if header["name"] == "Return-Path":
                    return header["value"].replace("<", "").replace(">", "")
            
            # If not found, try From header
            for header in message["payload"]["headers"]:
                if header["name"] == "From":
                    # Extract email from "Name <email>" format
                    from_value = header["value"]
                    if "<" in from_value and ">" in from_value:
                        return from_value.split("<")[1].split(">")[0]
                    return from_value
                    
            raise ValueError(f"No return address found for message {msg_id}")
            
        except HttpError as error:
            logger.error(f"Failed to get return address for message {msg_id}: {error}")
            raise GmailApiError(f"Failed to get return address: {error}")
        
    def get_message_thread(self, thread_id: str, user_id: str = "me") -> List[Dict[str, Any]]:
        """Get all messages in a thread.
        
        Args:
            thread_id: Thread ID
            user_id: User's email address or 'me'
            
        Returns:
            List of messages in the thread
            
        Raises:
            GmailApiError: If thread retrieval fails
        """
        try:
            with self._rate_limit():
                thread = self.service.users().threads().get(
                    userId=user_id, id=thread_id
                ).execute()
                
                return thread.get("messages", [])
                
        except HttpError as error:
            logger.error(f"Failed to get thread {thread_id}: {error}")
            raise GmailApiError(f"Failed to get thread: {error}")

    def add_labels(self, msg_id: str, labels: List[str], user_id: str = "me") -> Dict[str, Any]:
        """Add labels to a message.
        
        Args:
            msg_id: Message ID
            labels: List of label IDs to add
            user_id: User's email address or 'me'
            
        Returns:
            Modified message details
            
        Raises:
            GmailApiError: If label modification fails
        """
        try:
            with self._rate_limit():
                return self.service.users().messages().modify(
                    userId=user_id,
                    id=msg_id,
                    body={"addLabelIds": labels}
                ).execute()
                
        except HttpError as error:
            logger.error(f"Failed to add labels to message {msg_id}: {error}")
            raise GmailApiError(f"Failed to add labels: {error}")

    def remove_labels(self, msg_id: str, labels: List[str], user_id: str = "me") -> Dict[str, Any]:
        """Remove labels from a message.
        
        Args:
            msg_id: Message ID
            labels: List of label IDs to remove
            user_id: User's email address or 'me'
            
        Returns:
            Modified message details
            
        Raises:
            GmailApiError: If label modification fails
        """
        try:
            with self._rate_limit():
                return self.service.users().messages().modify(
                    userId=user_id,
                    id=msg_id,
                    body={"removeLabelIds": labels}
                ).execute()
                
        except HttpError as error:
            logger.error(f"Failed to remove labels from message {msg_id}: {error}")
            raise GmailApiError(f"Failed to remove labels: {error}")

    def get_user_labels(self, user_id: str = "me") -> List[Dict[str, Any]]:
        """Get all labels for the user.
        
        Args:
            user_id: User's email address or 'me'
            
        Returns:
            List of label details
            
        Raises:
            GmailApiError: If label retrieval fails
        """
        try:
            with self._rate_limit():
                results = self.service.users().labels().list(userId=user_id).execute()
                return results.get("labels", [])
                
        except HttpError as error:
            logger.error(f"Failed to get user labels: {error}")
            raise GmailApiError(f"Failed to get user labels: {error}")

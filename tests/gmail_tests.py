import os
import unittest
import base64
from unittest.mock import patch, MagicMock

# Import the classes from your module
from vinescribe.services.gmail import (
    GmailAuthService, 
    GmailMessageService,
    GetCredentialsException,
    NoRefreshTokenException,
    SCOPES
)

class TestGmailAuthService(unittest.TestCase):
    """Tests for the GmailAuthService class."""

    def setUp(self):
        # Setup test environment variables
        os.environ["GMAIL_AUTH_FILE"] = "test_token.json"
        os.environ["GMAIL_CREDENTIALS_FILE"] = "test_credentials.json"


    def tearDown(self): 
        # Remove test environment variables
        if "GMAIL_AUTH_FILE" in os.environ:
            del os.environ["GMAIL_AUTH_FILE"]
        if "GMAIL_CREDENTIALS_FILE" in os.environ:
            del os.environ["GMAIL_CREDENTIALS_FILE"]

    @patch('os.path.exists')
    def test_missing_credentials_file(self, mock_exists):
        """Test error when credentials file is missing."""
        # Token file doesn't exist, and neither does credentials file
        mock_exists.return_value = False
        
        with self.assertRaises(FileNotFoundError):
            auth_service = GmailAuthService()

    @patch('os.path.exists')
    def test_missing_token_file(self, mock_exists):
        """Test error when token file is missing."""
        # Token file doesn't exist, but credentials file does
        mock_exists.side_effect = lambda path: path == "test_credentials.json"
        
        with self.assertRaises(FileNotFoundError):
            auth_service = GmailAuthService()

    @patch('os.path.exists')
    @patch('google.oauth2.credentials.Credentials.from_authorized_user_file')
    def test_no_refresh_token(self, mock_from_authorized_user_file, mock_exists):
        """Test error when no refresh token is available."""
        mock_exists.return_value = True
       
        mock_creds = MagicMock()
        mock_creds.valid = False
        mock_creds.expired = True
        mock_creds.refresh_token = None

        mock_from_authorized_user_file.return_value = mock_creds
        with self.assertRaises(NoRefreshTokenException):
            GmailAuthService()

class TestGmailMessageService(unittest.TestCase):
    """Tests for the GmailMessageService class."""

    @patch('vinescribe.services.gmail.GmailAuthService')
    @patch('vinescribe.services.gmail.GmailMessageService.get_message_attachment')
    def test_process_attachment_part(self, mock_get_message_attachment, mock_auth_service):
        """Test extracting attachment data from a mock attachment part."""
        mock_get_message_attachment.return_value = {
            "data": base64.urlsafe_b64encode(b"mock_attachment_data").decode("UTF-8"),
            "size": 20
        }

        attachment_part = {
            "filename": "mock_file.txt",
            "mimeType": "text/plain",
            "body": {
                "attachmentId": "mock_attachment_id"
            }
        }

        message = {
            "id": "mock_message_id",
            "payload": {
                "headers": [],
                "parts": [attachment_part]
            }
        }

        service = GmailMessageService(mock_auth_service)

        extracted_attachment = service._process_attachment_part(
            part=attachment_part,
            message=message,
            user_id="me",
            mimetype_filter=None
        )

        self.assertIsNotNone(extracted_attachment)
        self.assertEqual(extracted_attachment["filename"], "mock_file.txt")
        self.assertEqual(extracted_attachment["data"], b"mock_attachment_data")
        self.assertEqual(extracted_attachment["size"], 20)

    @patch('vinescribe.services.gmail.GmailAuthService')
    def test_extract_message_parts(self, mock_auth_service):
        """Test extracting message parts from a mock message."""
        message = {
            "id": "mock_message_id",
            "payload": {
                "headers": [],
                "parts": [
                    {
                        "partId": "1",
                        "mimeType": "text/plain",
                        "filename": "",
                        "body": {"size": 20, "data": "mock_data_1"},
                    },
                    {
                        "partId": "2",
                        "mimeType": "text/html",
                        "filename": "",
                        "body": {"size": 30, "data": "mock_data_2"},
                    },
                ],
            },
        }

        service = GmailMessageService(mock_auth_service)

        parts = service._extract_message_parts(message)
        print(parts)
        self.assertEqual(len(parts), 3)
        self.assertEqual(parts[1]["partId"], "1")
        self.assertEqual(parts[2]["partId"], "2")

if __name__ == "__main__":
    unittest.main()
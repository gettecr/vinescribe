import unittest
from unittest.mock import Mock, patch, MagicMock
import json
from google.genai import types
import logging
import io
import tempfile
import os
from io import BytesIO
from PIL import Image

from vinescribe.services.gmail import GmailMessageService
from vinescribe.services.llm import LLMService

# Import the class under test
from vinescribe.main import VineScribeEmailer, load_wine_database

class TestVineScribeEmailer(unittest.TestCase):
    def setUp(self):
        # Create mock services
        self.mock_email_client = Mock(spec=GmailMessageService)
        self.mock_llm = Mock(spec=LLMService)
        
        # Configure the mock LLM service with rate limiting attributes
        self.mock_llm.rate_limit_calls = 10
        self.mock_llm.rate_limit_period = 60
        self.mock_llm.client = Mock()
        self.mock_llm.client.models = Mock()
        
        # Create the class under test
        self.emailer = VineScribeEmailer(email_client=self.mock_email_client, llm=self.mock_llm)
        
        # Sample data for tests
        self.sample_messages = [
            {"id": "msg1", "threadId": "thread1"},
            {"id": "msg2", "threadId": "thread2"},
            {"id": "msg3", "threadId": "thread3"}
        ]
        
        self.sample_message_content = {
            "payload": {
                "headers": [
                    {"name": "Subject", "value": "Test Subject with keyword: page"},
                    {"name": "From", "value": "test@example.com"}
                ]
            }
        }
        
        self.sample_attachment = {
            "mimetype": "image/jpeg",
            "data": b"fake_image_data"
        }
        
        self.sample_wine_data = [
            {
                "name": "Château Test",
                "vintage": "2018",
                "producer": "Test Winery",
                "varietal": "Merlot",
                "rating": 4.5,
                "notes": "Excellent wine with hints of berry",
                "date_consumed": "2023-04-15"
            }
        ]
        
    def test_get_messages_with_keyword_no_match(self):
        # Setup
        message_content_no_match = {
            "payload": {
                "headers": [
                    {"name": "Subject", "value": "No keyword here"},
                    {"name": "From", "value": "test@example.com"}
                ]
            }
        }
        self.mock_email_client.get_message.return_value = message_content_no_match
        
        # Execute
        result = self.emailer.get_messages_with_keyword(self.sample_messages, "page")
        
        # Assert
        self.assertEqual(len(result), 0)
        self.mock_email_client.get_message.assert_called()
        
    def test_get_messages_with_keyword_unsupported_field(self):
        # Execute
        result = self.emailer.get_messages_with_keyword(self.sample_messages, "page", search_in="body")
        
        # Assert
        self.assertEqual(len(result), 0)
        self.mock_email_client.get_message.assert_not_called()
        

class TestLoadWineDatabase(unittest.TestCase):
    def test_load_existing_database(self):
        # Setup - create a temp file with sample data
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as tmp:
            json.dump([{"name": "Test Wine"}], tmp)
            tmp_path = tmp.name
        
        # Execute
        result = load_wine_database(tmp_path)
        
        # Assert
        self.assertEqual(result, [{"name": "Test Wine"}])
        
        # Clean up
        os.unlink(tmp_path)
    
    def test_load_nonexistent_database(self):
        # Execute with a path that doesn't exist
        result = load_wine_database("nonexistent_file.json")
        
        # Assert
        self.assertEqual(result, [])
    
    def test_load_invalid_json_database(self):
        # Setup - create a temp file with invalid JSON
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as tmp:
            tmp.write("This is not valid JSON")
            tmp_path = tmp.name
        
        # Execute
        result = load_wine_database(tmp_path)
        
        # Assert
        self.assertEqual(result, [])
        
        # Clean up
        os.unlink(tmp_path)
    
    def test_load_non_list_database(self):
        # Setup - create a temp file with non-list JSON
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as tmp:
            json.dump({"name": "Single Wine Object"}, tmp)
            tmp_path = tmp.name
        
        # Execute
        result = load_wine_database(tmp_path)
        
        # Assert
        self.assertEqual(result, [{"name": "Single Wine Object"}])
        
        # Clean up
        os.unlink(tmp_path)


if __name__ == '__main__':
    unittest.main()
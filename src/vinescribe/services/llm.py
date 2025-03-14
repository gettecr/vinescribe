from google import genai
from abc import ABC, abstractmethod
import dotenv
import os

dotenv.load_dotenv()


# TODO: Convert this to a universal LLM structure instead of gemini specific
class LLMService(ABC):
    def __init__(self):
        self.rate_limit_calls = 10
        self.rate_limit_period = 60  # seconds

    @abstractmethod
    def set_client(self):
        raise NotImplementedError


class GeminiService:
    def __init__(self, api_key=None):
        self.api_key = api_key if api_key else os.getenv("GOOGLE_API_KEY")
        self.client = self.set_client()
        self.rate_limit_calls = 10
        self.rate_limit_period = 60  # seconds

    def set_client(self):
        return genai.Client(api_key=self.api_key)

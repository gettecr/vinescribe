# VineScribe

An AI-powered wine tasting companion that digitizes handwritten reviews and provides wine comparisons based on your tasting notes.

## Features

### 📸 Review Capture
- Email photos of handwritten wine tasting notes
- Automatic text extraction and digital archival
- Maintains personal wine tasting repository

### 🍷 Smart Recommendations
- Send wine label photos for instant comparisons
- Reviews your tasting notes and returns those or similar based on your taste profile
- Email-based interaction for easy access

## How It Works

1. **Adding Reviews**
   - Take a photo of your handwritten wine tasting notes
   - Email the image to your designated VineScribe address
   - AI extracts and stores your tasting notes

2. **Getting Recommendations**
   - Snap a photo of any wine label
   - Send it to VineScribe
   - Receive similar wines and relevant tasting notes from your collection


The project structure is as follows:

```
vinescribe/
├── src/
│   ├── vinescribe/
│   │   ├── __init__.py
│   │   ├── main.py
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   └── wine.py
│   │   ├── services/
│   │   │   ├── __init__.py
|   |   |   ├── image.py
|   |   |   ├── llm.py
│   │   │   └── gmail.py
├── tests/
│   ├── __init__.py
│   ├── gmail_tests.py
│   └── vinescribe_tests.py
├── .env.example
├── pyproject.toml
├── README.md
└── poetry.lock
```
## Setup

1. Clone the repository:
    ```sh
    git clone <repository-url>
    cd vinescribe
    ```

2. Install dependencies using Poetry:
    ```sh
    poetry install
    ```

3. Set up environment variables:
    - Copy the  file to your project root.
    - Update the values in  as needed.
  
## Get Gmail API Credentials

Follow the google documentation for setting up a desktop application in your google could account:
https://developers.google.com/gmail/api/quickstart/python

- Follow directions to get "credentials.json"
- add "credentials.json" to your working directory
- add the path to "credentials.json" to your .env file as GMAIL_CREDENTIALS_FILE
- The first time you run the app, you will need to log in via browser to get a token.json file

## Running the Project

To run the main application, use:
```sh
poetry run python src/vinescribe/main.py
```

## Testing

To run tests, use the following command:

```sh
poetry run pytest tests/*
```

## Deployment

To deploy the application, follow these steps:

1. Ensure all dependencies are installed:
    ```sh
    poetry install
    ```

2. Build the project:
    ```sh
    poetry build
    ```

3. Deployment scripts and service files are located in the deploy directory. Use deploy.sh to deploy the service as a systemd service

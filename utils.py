def highlight(text, color="blue"):
    from termcolor import colored
    return colored(text, color)


import requests
from bs4 import BeautifulSoup
import google.generativeai as genai

def get_website_content(url):
    """
    Crawl the website and extract up to 500 words of paragraph content.
    """
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Linux; Android 10; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36'
        }
        # Make a request to the website
        response = requests.get(url, headers=headers, timeout=10, verify=False)

        # Parse the HTML content using BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')

        # Extract all paragraph content
        paragraphs = soup.find_all('p')
        content = []

        # Collect text from paragraphs up to 500 words
        word_count = 0
        for p in paragraphs:
            text = p.get_text(strip=True)
            words = text.split()
            word_count += len(words)
            if word_count <= 500:
                content.append(text)
            else:
                # Include only enough words to reach 500
                remaining_words = 500 - (word_count - len(words))
                content.append(" ".join(words[:remaining_words]))
                break

        return " ".join(content)  # Join all collected paragraphs into a single string
    except Exception as e:
        print(f"Error crawling website: {e}")
        return None

def classify_content_with_gemini(content, api_key="AIzaSyBYpNf7L0sPbuRkr7FlLu0p8ZigNljY5Io"):
    """
    Classify the website content using Gemini API.
    """
    try:
        # Configure Generative AI with the API key
        genai.configure(api_key=api_key)

        # Initialize the GenerativeModel for Gemini 1.5 Flash
        model = genai.GenerativeModel("gemini-1.5-flash")

        # Prepare the prompt to classify the content
        prompt = ("portfolio, corporate, ecommerce, blogs, social_media, educational, government, "
                  "entertainment, test_dummy. Based on the above mentioned list classify the following content "
                  f"into any one category. only give the classified category name as response make it all lowercase. The content is: {content}")

        # Call the model to classify the content
        response = model.generate_content(prompt)

        # Return the classified category
        return response.text.strip()  # Strip whitespace or newline characters
    except Exception as e:
        print(f"Error classifying content: {e}")
        return None

def generate_payload_file_path(url, attack_type):
    """
    Crawl website, classify content, and return the custom payload file path.
    """
    # Get website content
    content = get_website_content(url)

    if content:
        # Classify the content
        classification = classify_content_with_gemini(content)

        if classification:
            # Construct and return the file path
            file_path = f"custompayloads/custompayloads/{classification}/payload.txt"
            return file_path
        else:
            return "Error: Unable to classify content."
    #sometimes certain websites block scraping
    else:
        file_path = "custompayloads/custompayloads/test_dummy/payload.txt"
        return file_path


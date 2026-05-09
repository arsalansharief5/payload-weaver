import os

import requests
from bs4 import BeautifulSoup

try:
    from openai import OpenAI
except Exception:
    OpenAI = None


SITE_CATEGORIES = [
    "portfolio",
    "corporate",
    "ecommerce",
    "blogs",
    "social_media",
    "educational",
    "government",
    "entertainment",
]


def highlight(text, color="blue"):
    from termcolor import colored
    return colored(text, color)


def get_ai_api_key():
    env_key = (
        os.getenv("OPENAI_API_KEY")
        or os.getenv("AI_API_KEY")
        or _read_api_key_from_env_file()
    )
    return env_key


def _read_api_key_from_env_file():
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.exists(env_path):
        return None

    try:
        with open(env_path, "r", encoding="utf-8") as env_file:
            for raw_line in env_file:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue

                if line.startswith("OPENAI_API_KEY="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")

                if line.startswith("$env:OPENAI_API_KEY="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    except OSError:
        return None

    return None


def get_openai_client(api_key=None):
    api_key = api_key or get_ai_api_key()
    if not api_key or OpenAI is None:
        return None

    return OpenAI(api_key=api_key)

def get_website_content(url, max_words=700):
    """
    Crawl the website and extract up to max_words of paragraph content.
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

        # Collect text from paragraphs up to max_words
        word_count = 0
        for p in paragraphs:
            text = p.get_text(strip=True)
            words = text.split()
            word_count += len(words)
            if word_count <= max_words:
                content.append(text)
            else:
                # Include only enough words to reach max_words
                remaining_words = max_words - (word_count - len(words))
                content.append(" ".join(words[:remaining_words]))
                break

        return " ".join(content)  # Join all collected paragraphs into a single string
    except Exception as e:
        print(f"Error crawling website: {e}")
        return None

def classify_content_with_openai(content, api_key=None):
    """
    Classify website content into one of the supported categories.
    """
    try:
        client = get_openai_client(api_key)
        if client is None:
            return None

        response = client.responses.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4.1-mini"),
            input=[
                {
                    "role": "system",
                    "content": [
                        {
                            "type": "input_text",
                            "text": (
                                "You classify websites for defensive security scanning. "
                                f"Choose exactly one category from: {', '.join(SITE_CATEGORIES)}. "
                                "Return only the category name in lowercase."
                            ),
                        }
                    ],
                },
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "input_text",
                            "text": f"Website content:\n{content}",
                        }
                    ],
                },
            ],
            max_output_tokens=20,
        )
        classification = (response.output_text or "").strip().lower()
        if classification in SITE_CATEGORIES:
            return classification
        return None
    except Exception as e:
        print(f"Error classifying content with OpenAI: {e}")
        return None


def classify_website(url, api_key=None):
    content = get_website_content(url)
    if not content:
        return None, None

    classification = classify_content_with_openai(content, api_key=api_key)
    return classification, content


def generate_ai_scan_summary(target_url, site_category, crawl_data, vulnerabilities, api_key=None):
    """
    Create a plain-language AI summary from scan results.
    """
    try:
        client = get_openai_client(api_key)
        if client is None:
            return None

        significant_findings = []
        for vulnerability in vulnerabilities[:12]:
            significant_findings.append(
                f"- {vulnerability.get('name', 'Unknown finding')} | "
                f"Risk: {vulnerability.get('risk', 'Unknown')} | "
                f"URL: {vulnerability.get('url', 'N/A')} | "
                f"Description: {vulnerability.get('description', 'N/A')} | "
                f"Suggested fix from scanner: {vulnerability.get('solution', 'N/A')}"
            )

        if not significant_findings:
            significant_findings.append("- No non-trivial findings were returned by the scanner.")

        response = client.responses.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4.1-mini"),
            input=[
                {
                    "role": "system",
                    "content": [
                        {
                            "type": "input_text",
                            "text": (
                                "You are helping summarize an authorized defensive web security scan. "
                                "Write practical remediation guidance only. Do not include exploit steps. "
                                "Use these section labels exactly: Executive Summary:, Category Insight:, "
                                "Priority Actions:, AI Suggestions:."
                            ),
                        }
                    ],
                },
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "input_text",
                            "text": (
                                f"Target URL: {target_url}\n"
                                f"Site category: {site_category or 'Unknown'}\n"
                                f"URLs crawled: {crawl_data.get('num_crawls', 0)}\n"
                                f"Findings:\n" + "\n".join(significant_findings)
                            ),
                        }
                    ],
                },
            ],
            max_output_tokens=700,
        )
        return (response.output_text or "").strip() or None
    except Exception as e:
        print(f"Error generating AI summary with OpenAI: {e}")
        return None

def generate_payload_file_path(url, attack_type):
    """
    Legacy helper retained for backward compatibility.
    """
    classification, _ = classify_website(url)
    if classification:
        return f"custompayloads/custompayloads/{classification}/payload.txt"
    return "custompayloads/custompayloads/test_dummy/payload.txt"


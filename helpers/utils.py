import requests
from bs4 import BeautifulSoup
import logging
from config import VIRUSTOTAL_BASE_URL, API_KEY


def extract_urls(page_url):
    try:
        response = requests.get(page_url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        urls = [a['href'] for a in soup.find_all('a', href=True) if a['href'].startswith('http')]
        logging.info(f"{len(urls)} urls extracted.")
        return urls
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching URL: {str(e)}")
        return []


def scan_urls(urls):
    results = {}
    for url in urls:
        logging.info(f"Scanning: {url}")
        result = scan_url_with_virustotal(url)
        logging.info(f"Scanned: {url}")
        if result:
            results[url] = result
    return results


def scan_url_with_virustotal(url):
    try:
        payload = {"url": url}
        headers = {
            "accept": "application/json",
            'x-apikey': API_KEY,
            "content-type": "application/x-www-form-urlencoded"
        }
        response = requests.post(f'{VIRUSTOTAL_BASE_URL}/urls', data=payload, headers=headers, timeout=10)

        if response.status_code == 429:
            logging.warning(f"Rate limit exceeded.")
            return None
        response.raise_for_status()
        json_response = response.json()
        data = json_response.get('data')
        if data:
            return data.get('id')
        return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Error scanning URL with VirusTotal: {str(e)}")
        return None


def get_analysis_with_virustotal(analysis_id):
    try:
        headers = {
            "accept": "application/json",
            'x-apikey': API_KEY,
        }
        analysis_response = requests.get(f'{VIRUSTOTAL_BASE_URL}/analyses/{analysis_id}', headers=headers, timeout=10)
        analysis_response.raise_for_status()
        json_response = analysis_response.json()

        data = json_response.get('data')
        if data:
            attributes = data.get('attributes')
            if attributes:
                return attributes.get('results')
        return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching analysis from VirusTotal: {str(e)}")
        return None


def extract_analysis(urls):
    analysis_datas = {}
    for url, analysis_id in urls.items():
        result = get_analysis_with_virustotal(analysis_id)
        if result:
            analysis_datas[url] = result
    return analysis_datas

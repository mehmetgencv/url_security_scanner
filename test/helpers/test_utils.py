import unittest
from unittest.mock import patch, Mock

import requests

from helpers.utils import extract_urls, scan_urls, scan_url_with_virustotal, get_analysis_with_virustotal, extract_analysis


class TestUtils(unittest.TestCase):

    @patch('helpers.utils.requests.get')
    def test_extract_urls_success(self, mock_get):
        # Mock the response for a successful URL extraction
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '<a href="http://example.com">Example</a>'
        mock_get.return_value = mock_response

        urls = extract_urls('http://test.com')
        self.assertEqual(urls, ['http://example.com'])

    @patch('helpers.utils.requests.get')
    def test_extract_urls_failure(self, mock_get):
        mock_get.side_effect = requests.exceptions.RequestException("Connection error")
        urls = extract_urls('http://test.com')
        self.assertEqual(urls, [])

    @patch('helpers.utils.scan_url_with_virustotal')
    def test_scan_urls(self, mock_scan_url_with_virustotal):
        # Mock the VirusTotal scanning function
        mock_scan_url_with_virustotal.return_value = "12345"
        urls = ['http://example.com']
        results = scan_urls(urls)
        self.assertEqual(results, {'http://example.com': '12345'})

    @patch('helpers.utils.requests.post')
    def test_scan_url_with_virustotal_success(self, mock_post):
        # Mock the response for a successful VirusTotal scan
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'data': {'id': '12345'}}
        mock_post.return_value = mock_response

        result = scan_url_with_virustotal('http://example.com')
        self.assertEqual(result, '12345')

    @patch('helpers.utils.requests.post')
    def test_scan_url_with_virustotal_rate_limit(self, mock_post):
        mock_response = Mock()
        mock_response.status_code = 429
        mock_post.return_value = mock_response

        result = scan_url_with_virustotal('http://example.com')
        self.assertIsNone(result)

    @patch('helpers.utils.requests.get')
    def test_get_analysis_with_virustotal_success(self, mock_get):
        # Mock the response for a successful analysis fetch
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'data': {'attributes': {'results': 'clean'}}}
        mock_get.return_value = mock_response

        result = get_analysis_with_virustotal('12345')
        self.assertEqual(result, 'clean')

    @patch('helpers.utils.requests.get')
    def test_get_analysis_with_virustotal_failure(self, mock_get):
        mock_get.side_effect = requests.exceptions.RequestException("Connection error")
        result = get_analysis_with_virustotal('12345')
        self.assertIsNone(result)

    @patch('helpers.utils.get_analysis_with_virustotal')
    def test_extract_analysis(self, mock_get_analysis_with_virustotal):
        # Mock the analysis extraction process
        mock_get_analysis_with_virustotal.return_value = 'clean'
        urls = {'http://example.com': '12345'}
        results = extract_analysis(urls)
        self.assertEqual(results, {'http://example.com': 'clean'})


if __name__ == '__main__':
    unittest.main()

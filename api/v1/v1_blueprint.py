from flask import Blueprint, request, render_template, flash
import time
import logging
from helpers.utils import extract_urls, scan_urls, extract_analysis

v1 = Blueprint('v1', __name__)


@v1.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form.get('url')

        if not url:
            flash('All fields are required', 'danger')
            return render_template('index.html')

        try:
            urls = extract_urls(url)
            if not urls:
                flash('No URLs found', 'warning')
                return render_template('index.html')

            urls = scan_urls(urls)
            time.sleep(5)
            analysis_data = extract_analysis(urls)
            return render_template('results.html', report=analysis_data)
        except Exception as e:
            logging.error(f"Error during processing: {str(e)}")
            flash('An error occurred while processing your request', 'danger')

    return render_template('index.html')

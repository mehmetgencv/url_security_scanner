from dotenv import load_dotenv
import os

load_dotenv()

VIRUSTOTAL_BASE_URL = os.getenv('VIRUSTOTAL_BASE_URL')
SECRET_KEY = os.getenv('SECRET_KEY')
API_KEY = os.getenv('API_KEY')

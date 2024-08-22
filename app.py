import os
from flask import Flask
import logging
from api.v1.v1_blueprint import v1
from config import SECRET_KEY

app = Flask(__name__)
app.secret_key = SECRET_KEY

if not os.path.exists('logs'):
    os.makedirs('logs')


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler("logs/app.log"),
        logging.StreamHandler()
    ]
)

app.register_blueprint(v1, url_prefix='/api/v1')


@app.route('/', methods=['GET'])
def index():
    welcome_message = "Welcome to the URL Security Scanner! Use this tool to scan URLs for security threats."
    return welcome_message


if __name__ == '__main__':
    app.run(debug=True)

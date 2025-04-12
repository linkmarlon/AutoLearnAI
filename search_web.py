import requests
from bs4 import BeautifulSoup
import html
from security import sanitize_input
import logging

logging.basicConfig(
    filename='data/errors.log',
    level=logging.ERROR,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('SearchWeb')

def search_web(query):
    try:
        sanitized_query = sanitize_input(query)
        url = f'https://www.google.com/search?q={sanitized_query}'
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        results = [html.escape(p.text) for p in soup.find_all('p')[:5] if p.text.strip()]
        return '\n'.join(results) or "Não encontrei nada."
    except Exception as e:
        logger.error(f"Erro na busca web para '{query}': {str(e)}")
        return f"[Erro na busca: {e}]"
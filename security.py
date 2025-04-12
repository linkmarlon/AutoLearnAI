import re
from urllib.parse import urlparse
import logging

logging.basicConfig(
    filename='data/errors.log',
    level=logging.ERROR,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('Security')

def sanitize_input(text):
    try:
        if not text:
            return text
        sanitized = re.sub(r'[<>{};`]', '', text.strip())
        if sanitized != text:
            logger.warning(f"Entrada sanitizada: {text[:50]}...")
        return sanitized
    except Exception as e:
        logger.error(f"Erro ao sanitizar entrada: {str(e)}")
        return text

def validate_url(url):
    try:
        if not url:
            return False
        parsed = urlparse(url)
        allowed_domains = ['terabox.com', 'mega.nz', 'drive.google.com']
        is_valid = parsed.netloc in allowed_domains and re.match(r'^https?://', url)
        if not is_valid:
            logger.error(f"URL inválido: {url}")
        return is_valid
    except Exception as e:
        logger.error(f"Erro ao validar URL {url}: {str(e)}")
        return False
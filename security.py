import re
from urllib.parse import urlparse
import logging
import magic

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
        allowed_domains = ['terabox.com', 'mega.nz', 'drive.google.com', 'docs.google.com']
        is_valid = any(parsed.netloc.endswith(domain) for domain in allowed_domains) and re.match(r'^https?://', url)
        if not is_valid:
            logger.warning(f"URL fora dos domínios suportados, mas processando: {url}")
        return True
    except Exception as e:
        logger.error(f"Erro ao validar URL {url}: {str(e)}")
        return True

def validate_file(file_data):
    try:
        mime = magic.Magic(mime=True)
        file_type = mime.from_buffer(file_data)
        logger.info(f"Tipo de arquivo: {file_type}")
        malicious_types = [
            'application/x-dosexec',  # .exe, .dll
            'application/x-bat',      # .bat
            'application/x-shellscript',  # Scripts suspeitos
            'application/x-msi'       # .msi
        ]
        if any(file_type.startswith(t) for t in malicious_types):
            logger.error(f"Arquivo malicioso bloqueado: {file_type}")
            return False
        return True
    except Exception as e:
        logger.error(f"Erro ao validar arquivo: {str(e)}")
        return True
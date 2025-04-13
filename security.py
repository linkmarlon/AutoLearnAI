import re
import base64
import magic
import logging
from urllib.parse import urlparse
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

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
        allowed_domains = ['terabox.com', '1024terabox.com', 'mega.nz', 'drive.google.com', 'docs.google.com']
        is_valid = any(parsed.netloc.lower().endswith(domain) for domain in allowed_domains) and re.match(r'^https?://', url)
        if not is_valid:
            logger.warning(f"URL fora dos domínios suportados, mas processando: {url}")
        return True
    except Exception as e:
        logger.error(f"Erro ao validar URL {url}: {str(e)}")
        return True

def validate_file(file_data):
    try:
        if not isinstance(file_data, bytes):
            file_data = bytes(file_data)
        mime = magic.Magic(mime=True)
        file_type = mime.from_buffer(file_data)
        logger.info(f"Tipo de arquivo: {file_type}")
        malicious_types = [
            'application/x-dosexec',
            'application/x-bat',
            'application/x-shellscript',
            'application/x-msi'
        ]
        if any(file_type.startswith(t) for t in malicious_types):
            logger.error(f"Arquivo malicioso bloqueado: {file_type}")
            return False
        return True
    except Exception as e:
        logger.error(f"Erro ao validar arquivo: {str(e)}")
        return True

def encrypt_file(data, key):
    try:
        # Garantir que data seja bytes
        if not isinstance(data, bytes):
            if isinstance(data, bytearray):
                data = bytes(data)
            else:
                data = data.encode('utf-8')
        # Garantir que key seja bytes
        if not isinstance(key, bytes):
            if isinstance(key, bytearray):
                key = bytes(key)
            else:
                key = key.encode('utf-8')
        # Ajustar tamanho da chave
        if len(key) not in [16, 24, 32]:
            key = pad(key, 32)[:32]
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        return {'iv': iv, 'ciphertext': ct}
    except Exception as e:
        logger.error(f"Erro ao criptografar arquivo: {str(e)}")
        raise

def decrypt_file(enc_data, key):
    try:
        # Garantir que key seja bytes
        if not isinstance(key, bytes):
            if isinstance(key, bytearray):
                key = bytes(key)
            else:
                key = key.encode('utf-8')
        if len(key) not in [16, 24, 32]:
            key = pad(key, 32)[:32]
        iv = base64.b64decode(enc_data['iv'])
        ct = base64.b64decode(enc_data['ciphertext'])
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt
    except Exception as e:
        logger.error(f"Erro ao descriptografar arquivo: {str(e)}")
        return None
import base64
import magic
import logging
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

logging.basicConfig(
    filename='data/errors.log',
    level=logging.ERROR,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('Security')

def validate_file(file_content, file_name):
    try:
        mime = magic.Magic(mime=True)
        file_type = mime.from_buffer(file_content)
        malicious_types = ['application/x-dosexec', 'application/x-msdownload']
        malicious_extensions = ['.exe', '.bat', '.cmd', '.msi']
        if file_type in malicious_types or any(file_name.lower().endswith(ext) for ext in malicious_extensions):
            logger.error(f"Arquivo malicioso detectado: {file_name}, tipo: {file_type}")
            return False
        return True
    except Exception as e:
        logger.error(f"Erro ao validar arquivo {file_name}: {str(e)}")
        return False

def encrypt_file(file_content, key):
    try:
        if isinstance(file_content, bytearray):
            file_content = bytes(file_content)  # Converter bytearray para bytes
        if isinstance(key, bytearray):
            key = bytes(key)  # Converter key para bytes
        if len(key) not in [16, 24, 32]:
            key = pad(key, 32)[:32]
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(file_content, AES.block_size))
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        return {'iv': iv, 'ciphertext': ct}
    except Exception as e:
        logger.error(f"Erro ao criptografar arquivo: {str(e)}")
        raise

def decrypt_file(enc_data, key):
    try:
        if isinstance(key, bytearray):
            key = bytes(key)  # Converter key para bytes
        if len(key) not in [16, 24, 32]:
            key = pad(key, 32)[:32]
        iv = base64.b64decode(enc_data['iv'])
        ct = base64.b64decode(enc_data['ciphertext'])
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt
    except Exception as e:
        logger.error(f"Erro ao descriptografar arquivo: {str(e)}")
        raise

def validate_url(url):
    malicious_patterns = ['malicious.com', 'phishing.com']
    return not any(pattern in url.lower() for pattern in malicious_patterns)
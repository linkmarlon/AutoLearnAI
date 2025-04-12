import sqlite3
from Crypto.Cipher import AES
import base64
import os
from security import sanitize_input
import logging

logging.basicConfig(
    filename='data/errors.log',
    level=logging.ERROR,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('KnowledgeDB')

def encrypt_text(text, key):
    try:
        cipher = AES.new(base64.b64decode(key), AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(text.encode())
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode()
    except Exception as e:
        logger.error(f"Erro ao criptografar texto: {str(e)}")
        raise

def decrypt_text(encrypted_text, key):
    try:
        data = base64.b64decode(encrypted_text)
        nonce = data[:16]
        tag = data[16:32]
        ciphertext = data[32:]
        cipher = AES.new(base64.b64decode(key), AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()
    except Exception as e:
        logger.error(f"Erro ao descriptografar texto: {str(e)}")
        return ""

def save_knowledge(query, response, encryption_key):
    try:
        os.makedirs('data/', exist_ok=True)
        conn = sqlite3.connect('data/knowledge.db')
        c = conn.cursor()
        c.execute('CREATE TABLE IF NOT EXISTS knowledge (query TEXT, response TEXT)')
        encrypted_query = encrypt_text(sanitize_input(query), encryption_key)
        encrypted_response = encrypt_text(sanitize_input(response), encryption_key)
        c.execute('INSERT INTO knowledge VALUES (?, ?)', (encrypted_query, encrypted_response))
        conn.commit()
    except Exception as e:
        logger.error(f"Erro ao salvar conhecimento: {str(e)}")
    finally:
        conn.close()

def load_knowledge(query, encryption_key):
    try:
        conn = sqlite3.connect('data/knowledge.db')
        c = conn.cursor()
        c.execute('SELECT query, response FROM knowledge')
        sanitized_query = sanitize_input(query)
        for encrypted_query, encrypted_response in c.fetchall():
            decrypted_query = decrypt_text(encrypted_query, encryption_key)
            if decrypted_query == sanitized_query:
                return decrypt_text(encrypted_response, encryption_key)
        return ""
    except Exception as e:
        logger.error(f"Erro ao carregar conhecimento: {str(e)}")
        return ""
    finally:
        conn.close()
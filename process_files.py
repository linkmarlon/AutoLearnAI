import os
import chromadb
from sentence_transformers import SentenceTransformer
import pdfplumber
from docx import Document
from pptx import Presentation
import zipfile
import rarfile
import py7zr
import tarfile
import gzip
import bz2
import requests
from io import BytesIO
import mega
from gdown import download
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import magic
from security import validate_url, validate_file
import logging
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload
import io

logging.basicConfig(
    filename='data/errors.log',
    level=logging.ERROR,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ProcessFiles')

client = chromadb.Client()
collection = None

def get_file_hash(data):
    try:
        data = bytes(data) if not isinstance(data, bytes) else data
        hasher = hashlib.md5()
        hasher.update(data)
        return hasher.hexdigest()
    except Exception as e:
        logger.error(f"Erro ao calcular hash: {str(e)}")
        raise

def encrypt_file(data, key):
    try:
        data = bytes(data) if not isinstance(data, bytes) else data
        cipher = AES.new(base64.b64decode(key), AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return cipher.nonce + tag + ciphertext
    except Exception as e:
        logger.error(f"Erro ao criptografar arquivo: {str(e)}")
        raise

def decrypt_file(encrypted_data, key):
    try:
        nonce = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        cipher = AES.new(base64.b64decode(key), AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except Exception as e:
        logger.error(f"Erro ao descriptografar arquivo: {str(e)}")
        return None

def detect_source(url):
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()
        if 'terabox.com' in netloc:
            return "Terabox"
        elif 'mega.nz' in netloc:
            return "MEGA"
        elif 'drive.google.com' in netloc:
            return "Google Drive"
        elif 'docs.google.com' in netloc:
            return "Google Docs"
        logger.warning(f"Fonte desconhecida: {url}")
        return None
    except Exception as e:
        logger.error(f"Erro ao detectar fonte de {url}: {str(e)}")
        return None

def download_from_terabox(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        download_links = [a['href'] for a in soup.find_all('a', href=True) if 'sharing/link' in a['href']]
        file_data = []
        for link in download_links:
            file_response = requests.get(link, timeout=10)
            file_response.raise_for_status()
            file_data.append(bytes(file_response.content))
        return file_data if file_data else [bytes(response.content)]
    except Exception as e:
        logger.error(f"Erro ao baixar do Terabox: {str
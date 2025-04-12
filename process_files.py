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
from security import validate_url
import logging

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
        hasher = hashlib.md5()
        hasher.update(data)
        return hasher.hexdigest()
    except Exception as e:
        logger.error(f"Erro ao calcular hash: {str(e)}")
        raise

def encrypt_file(data, key):
    try:
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

def validate_file(file_data):
    try:
        mime = magic.Magic(mime=True)
        file_type = mime.from_buffer(file_data)
        allowed_types = [
            'text/', 'application/pdf', 'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.ms-powerpoint', 'application/zip', 'application/x-rar-compressed',
            'application/x-7z-compressed', 'application/x-tar', 'application/gzip', 'application/x-bzip2'
        ]
        if not any(file_type.startswith(t) for t in allowed_types):
            logger.error(f"Tipo de arquivo inválido: {file_type}")
            return False
        return True
    except Exception as e:
        logger.error(f"Erro ao validar arquivo: {str(e)}")
        return False

def download_from_terabox(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return BytesIO(response.content)
    except Exception as e:
        logger.error(f"Erro ao baixar do Terabox: {str(e)}")
        raise

def download_file(source, url, encryption_key):
    try:
        temp_dir = 'data/'
        os.makedirs(temp_dir, exist_ok=True)
        file_path = os.path.join(temp_dir, 'temp_file')
        if source == "Terabox":
            if not validate_url(url):
                logger.error(f"URL do Terabox inválido: {url}")
                raise ValueError("Link do Terabox inválido")
            data = download_from_terabox(url).read()
            if validate_file(data):
                encrypted_data = encrypt_file(data, encryption_key)
                with open(file_path, 'wb') as f:
                    f.write(encrypted_data)
            else:
                raise ValueError("Arquivo não permitido")
        elif source == "MEGA":
            if not validate_url(url):
                logger.error(f"URL do MEGA inválido: {url}")
                raise ValueError("Link do MEGA inválido")
            m = mega.Mega().login()
            m.download_url(url, dest_path=temp_dir)
            temp_path = os.path.join(temp_dir, os.listdir(temp_dir)[0])
            with open(temp_path, 'rb') as f:
                data = f.read()
            if validate_file(data):
                encrypted_data = encrypt_file(data, encryption_key)
                with open(file_path, 'wb') as f:
                    f.write(encrypted_data)
            else:
                raise ValueError("Arquivo não permitido")
            os.remove(temp_path)
        elif source == "Google Drive":
            if not validate_url(url):
                logger.error(f"URL do Google Drive inválido: {url}")
                raise ValueError("Link do Google Drive inválido")
            download(url, temp_dir, quiet=False)
            temp_path = os.path.join(temp_dir, os.listdir(temp_dir)[0])
            with open(temp_path, 'rb') as f:
                data = f.read()
            if validate_file(data):
                encrypted_data = encrypt_file(data, encryption_key)
                with open(file_path, 'wb') as f:
                    f.write(encrypted_data)
            else:
                raise ValueError("Arquivo não permitido")
            os.remove(temp_path)
        else:
            logger.error(f"Fonte inválida: {source}")
            raise ValueError("Fonte não permitida")
        return file_path
    except Exception as e:
        logger.error(f"Erro ao baixar arquivo de {source}: {str(e)}")
        raise

def extract_text(file_path, encryption_key):
    try:
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        data = decrypt_file(encrypted_data, encryption_key)
        if not data:
            return "[Erro ao descriptografar]"
        temp_file = 'data/temp_decrypted'
        with open(temp_file, 'wb') as f:
            f.write(data)
    except Exception as e:
        logger.error(f"Erro ao preparar arquivo para extração: {str(e)}")
        return "[Erro ao processar arquivo]"

    ext = os.path.splitext(temp_file)[1].lower()
    try:
        if ext == '.pdf':
            with pdfplumber.open(temp_file) as pdf:
                return ''.join(page.extract_text() or '' for page in pdf.pages)
        elif ext == '.docx':
            doc = Document(temp_file)
            return '\n'.join(p.text for p in doc.paragraphs)
        elif ext == '.pptx':
            prs = Presentation(temp_file)
            return '\n'.join(shape.text for slide in prs.slides for shape in slide.shapes if hasattr(shape, 'text'))
        elif ext in ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2']:
            temp_extract = 'data/extracted/'
            os.makedirs(temp_extract, exist_ok=True)
            if ext == '.zip':
                with zipfile.ZipFile(temp_file, 'r') as z:
                    z.extractall(temp_extract)
            elif ext == '.rar' and rarfile:
                with rarfile.RarFile(temp_file, 'r') as r:
                    r.extractall(temp_extract)
            elif ext == '.7z':
                with py7zr.SevenZipFile(temp_file, 'r') as z:
                    z.extractall(temp_extract)
            elif ext == '.tar':
                with tarfile.open(temp_file, 'r') as t:
                    t.extractall(temp_extract)
            elif ext == '.gz':
                with gzip.open(temp_file, 'rb') as g, open(os.path.join(temp_extract, 'file'), 'wb') as f:
                    f.write(g.read())
            elif ext == '.bz2':
                with bz2.open(temp_file, 'rb') as b, open(os.path.join(temp_extract, 'file'), 'wb') as f:
                    f.write(b.read())
            texts = []
            for root, _, files in os.walk(temp_extract):
                for f in files:
                    texts.append(extract_text(os.path.join(root, f), encryption_key))
            return '\n'.join(texts)
        else:
            with open(temp_file, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
    except Exception as e:
        logger.error(f"Erro ao extrair texto de {file_path}: {str(e)}")
        return f"[Erro ao ler arquivo: {e}]"
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)

def process_files(files, source='Computador', shared=False, encryption_key=None):
    global collection
    texts = []
    file_hashes = []
    try:
        if shared and collection:
            existing_hashes = collection.get()['metadatas'] or []
            existing_hashes = [m.get('hash', '') for m in existing_hashes if m]
        else:
            existing_hashes = []

        if source == 'Computador':
            os.makedirs('data/', exist_ok=True)
            for file in files:
                try:
                    file_data = file.read()
                    if validate_file(file_data):
                        file_hash = get_file_hash(file_data)
                        if file_hash not in existing_hashes:
                            encrypted_data = encrypt_file(file_data, encryption_key)
                            file_path = os.path.join('data/', file.name)
                            with open(file_path, 'wb') as f:
                                f.write(encrypted_data)
                            texts.append(extract_text(file_path, encryption_key))
                            file_hashes.append(file_hash)
                        else:
                            logger.info(f"Arquivo duplicado ignorado: {file.name}")
                    else:
                        logger.error(f"Arquivo inválido: {file.name}")
                except Exception as e:
                    logger.error(f"Erro ao processar arquivo local {file.name}: {str(e)}")
        else:
            for url in files:
                if url.strip():
                    try:
                        file_path = download_file(source, url, encryption_key)
                        with open(file_path, 'rb') as f:
                            encrypted_data = f.read()
                        decrypted_data = decrypt_file(encrypted_data, encryption_key)
                        if decrypted_data:
                            file_hash = get_file_hash(decrypted_data)
                            if file_hash not in existing_hashes:
                                texts.append(extract_text(file_path, encryption_key))
                                file_hashes.append(file_hash)
                        else:
                            logger.error(f"Falha ao descriptografar arquivo de {url}")
                    except Exception as e:
                        logger.error(f"Erro ao processar URL {url}: {str(e)}")

        if texts:
            model = SentenceTransformer('all-MiniLM-L6-v2')
            embeddings = model.encode(texts)
            if collection is None:
                collection = client.create_collection('autolearnai')
            collection.add(
                documents=texts,
                embeddings=embeddings,
                ids=[f'doc_{i}' for i in range(len(texts))],
                metadatas=[{'hash': h} for h in file_hashes]
            )
        return collection
    except Exception as e:
        logger.critical(f"Erro fatal em process_files: {str(e)}", exc_info=True)
        raise

def get_collection():
    global collection
    try:
        if collection is None:
            try:
                collection = client.get_collection('autolearnai')
            except:
                collection = client.create_collection('autolearnai')
        return collection
    except Exception as e:
        logger.error(f"Erro ao acessar coleção: {str(e)}")
        raise
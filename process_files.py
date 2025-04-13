import os
import requests
import logging
from security import validate_file, encrypt_file, decrypt_file, validate_url
from mega import Mega
import gdown
import zipfile
import rarfile
import py7zr
import io

logging.basicConfig(
    filename='data/errors.log',
    level=logging.ERROR,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ProcessFiles')

def process_files(files, source="Auto-detectar", shared=False, encryption_key=None):
    os.makedirs('data/', exist_ok=True)
    processed_files = []

    for file in files:
        try:
            if source == "Auto-detectar" or source == "Link":
                if isinstance(file, str):
                    url = file
                    if not validate_url(url):
                        logger.error(f"URL suspeita detectada: {url}")
                        continue

                    if 'terabox.com' in url:
                        file_content = download_from_terabox(url)
                        file_name = url.split('/')[-1] or "terabox_file"
                    elif 'mega.nz' in url:
                        file_content = download_from_mega(url)
                        file_name = url.split('/')[-1] or "mega_file"
                    elif 'drive.google.com' in url:
                        file_content = download_from_google_drive(url)
                        file_name = url.split('/')[-2] or "gdrive_file"
                    else:
                        response = requests.get(url, stream=True, timeout=10)
                        response.raise_for_status()
                        file_content = response.content
                        file_name = url.split('/')[-1] or "downloaded_file"

                    if isinstance(file_content, bytearray):
                        file_content = bytes(file_content)  # Converter bytearray para bytes

                    if not validate_file(file_content, file_name):
                        continue

                    if encryption_key:
                        key = base64.b64decode(encryption_key)
                        enc_data = encrypt_file(file_content, key)
                        with open(f'data/{file_name}.enc', 'w') as f:
                            json.dump(enc_data, f)
                        processed_files.append(f'data/{file_name}.enc')
                    else:
                        with open(f'data/{file_name}', 'wb') as f:
                            f.write(file_content)
                        processed_files.append(f'data/{file_name}')

            elif source == "Computador":
                file_name = file["name"]
                file_content = file["read"]()
                if isinstance(file_content, bytearray):
                    file_content = bytes(file_content)  # Converter bytearray para bytes

                if not validate_file(file_content, file_name):
                    continue

                if encryption_key:
                    key = base64.b64decode(encryption_key)
                    enc_data = encrypt_file(file_content, key)
                    with open(f'data/{file_name}.enc', 'w') as f:
                        json.dump(enc_data, f)
                    processed_files.append(f'data/{file_name}.enc')
                else:
                    with open(f'data/{file_name}', 'wb') as f:
                        f.write(file_content)
                    processed_files.append(f'data/{file_name}')

            if file_name.endswith(('.zip', '.rar', '.7z')):
                extract_files(f'data/{file_name}', 'data/extracted/')

        except Exception as e:
            logger.error(f"Erro ao processar {file}: {str(e)}")
            continue

    return processed_files

def download_from_terabox(url):
    try:
        response = requests.get(url, stream=True, timeout=10)
        response.raise_for_status()
        return response.content
    except Exception as e:
        logger.error(f"Erro ao baixar arquivo de Terabox: {str(e)}")
        raise

def download_from_mega(url):
    try:
        mega = Mega()
        m = mega.login()
        file = m.download_url(url)
        return file.read()
    except Exception as e:
        logger.error(f"Erro ao baixar arquivo de MEGA: {str(e)}")
        raise

def download_from_google_drive(url):
    try:
        output = io.BytesIO()
        gdown.download(url, output, quiet=True)
        return output.getvalue()
    except Exception as e:
        logger.error(f"Erro ao baixar arquivo do Google Drive: {str(e)}")
        raise

def extract_files(file_path, extract_path):
    os.makedirs(extract_path, exist_ok=True)
    try:
        if file_path.endswith('.zip'):
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(extract_path)
        elif file_path.endswith('.rar'):
            with rarfile.RarFile(file_path, 'r') as rar_ref:
                rar_ref.extractall(extract_path)
        elif file_path.endswith('.7z'):
            with py7zr.SevenZipFile(file_path, 'r') as seven_zip:
                seven_zip.extractall(extract_path)
    except Exception as e:
        logger.error(f"Erro ao extrair arquivo {file_path}: {str(e)}")
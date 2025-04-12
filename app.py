import streamlit as st
from process_files import process_files, get_collection
from search_web import search_web
from knowledge_db import save_knowledge, load_knowledge
from security import sanitize_input, validate_url
from transformers import pipeline
import torch
from sentence_transformers import SentenceTransformer
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import logging
import os

os.makedirs('data', exist_ok=True)
logging.basicConfig(
    filename='data/errors.log',
    level=logging.ERROR,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('AutoLearnAI')

try:
    st.title("AutoLearnAI - Assistente Seguro e Colaborativo")
    st.write("Envie qualquer arquivo ou link de Terabox, MEGA, Google Drive, Google Docs ou PC. Pergunte e aprenda com a comunidade!")

    if 'encryption_key' not in st.session_state:
        st.session_state.encryption_key = base64.b64encode(get_random_bytes(32)).decode()

    source = st.selectbox("De onde vêm seus dados?", ["Terabox", "MEGA", "Google Drive", "Google Docs", "Computador"])
    file_urls = st.text_area("Cole links (um por linha)", help="Suporta pastas, arquivos e documentos!")
    if source == "Computador":
        uploaded_files = st.file_uploader("Escolha arquivos", accept_multiple_files=True, help="Qualquer formato, máximo 100MB")

    if st.button("Enviar Dados"):
        with st.spinner("Criptografando e processando..."):
            try:
                if source == "Computador" and uploaded_files:
                    for file in uploaded_files:
                        if file.size > 100 * 1024 * 1024:
                            logger.error(f"Arquivo muito grande: {file.name} ({file.size} bytes)")
                            st.error(f"Arquivo {file.name} excede 100MB.")
                            continue
                    collection = process_files(uploaded_files, source, shared=True, encryption_key=st.session_state.encryption_key)
                else:
                    sanitized_urls = [sanitize_input(url) for url in file_urls.split('\n') if url.strip()]
                    collection = process_files(sanitized_urls, source, shared=True, encryption_key=st.session_state.encryption_key)
                st.success("Dados adicionados à biblioteca!")
            except Exception as e:
                logger.error(f"Erro ao processar dados: {str(e)}", exc_info=True)
                st.error(f"Falha ao processar: {e}")

    model_options = ["Llama 3", "Mistral 7B", "Grok", "Gemma 2", "CodeLlama", "DeepSeek", "Falcon 7B", "Qwen 2", "Phi-3"]
    selected_model = st.selectbox("Qual IA usar?", model_options)

    query = st.text_input("O que você quer saber?", help="Ex.: Explique meu código VHDL")
    if query:
        with st.spinner("Gerando resposta segura..."):
            try:
                sanitized_query = sanitize_input(query)
                cipher = AES.new(base64.b64decode(st.session_state.encryption_key), AES.MODE_EAX)
                query_encrypted, tag = cipher.encrypt_and_digest(sanitized_query.encode())

                model_map = {
                    "Llama 3": "meta-llama/Llama-3-8B",
                    "Mistral 7B": "mistralai/Mixtral-7B-Instruct-v0.1",
                    "Gemma 2": "google/gemma-2-9b",
                    "CodeLlama": "codellama/CodeLlama-7b-hf",
                    "DeepSeek": "deepseek/DeepSeek-RAG",
                    "Falcon 7B": "tiiuae/falcon-7b",
                    "Qwen 2": "Qwen/Qwen2-7B",
                    "Phi-3": "microsoft/Phi-3-mini-4k-instruct"
                }
                pipe = None
                if selected_model != "Grok":
                    model_name = model_map.get(selected_model, "google/gemma-2-9b")
                    try:
                        pipe = pipeline("text-generation", model=model_name, device=0 if torch.cuda.is_available() else -1)
                    except Exception as e:
                        logger.error(f"Falha ao carregar modelo {selected_model}: {str(e)}")
                        st.warning(f"Erro com {selected_model}. Usando resposta padrão.")

                context = ""
                try:
                    collection = get_collection()
                    query_embedding = SentenceTransformer('all-MiniLM-L6-v2').encode([sanitized_query])[0]
                    results = collection.query(query_embeddings=[query_embedding], n_results=5)
                    context = '\n'.join(results['documents'][0]) if results['documents'] else ""
                except Exception as e:
                    logger.error(f"Erro ao buscar contexto: {str(e)}")

                saved_response = load_knowledge(sanitized_query, st.session_state.encryption_key)
                if saved_response:
                    context += '\nLembrei: ' + saved_response

                prompt = f"Contexto: {context}\nPergunta: {sanitized_query}\nResposta:"
                response = "Integração com Grok em desenvolvimento." if selected_model == "Grok" else (
                    pipe(prompt, max_length=500, truncation=True)[0]['generated_text'] if pipe else "Não consegui usar a IA."
                )

                if not context or len(context) < 50:
                    try:
                        web_results = search_web(sanitized_query)
                        prompt += f"\nInternet: {web_results}"
                        response = pipe(prompt, max_length=500, truncation=True)[0]['generated_text'] if pipe else response + "\nInternet: " + web_results
                        try:
                            collection = get_collection()
                            model = SentenceTransformer('all-MiniLM-L6-v2')
                            web_embedding = model.encode([web_results])[0]
                            collection.add(
                                documents=[web_results],
                                embeddings=[web_embedding],
                                ids=[f"web_{sanitized_query.replace(' ', '_')}"]
                            )
                        except Exception as e:
                            logger.error(f"Erro ao salvar resultado da web: {str(e)}")
                    except Exception as e:
                        logger.error(f"Erro na busca web: {str(e)}")

                st.write(response)
                save_knowledge(sanitized_query, response, st.session_state.encryption_key)
            except Exception as e:
                logger.error(f"Erro ao processar pergunta: {str(e)}")
                st.error(f"Erro ao responder: {e}")
except Exception as e:
    logger.critical(f"Erro fatal no app.py: {str(e)}")
    st.error("Erro crítico. Verifique data/errors.log.")
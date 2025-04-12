# AutoLearnAI
AutoLearnAI: IA grátis e segura que lê arquivos de Terabox, MEGA, Drive ou PC (PDF, ZIP, VHDL). Colabore em uma biblioteca compartilhada, pergunte e aprenda com buscas na web. Criptografia E2EE, anti-hackers e logs de erros. Escolha Llama 3, Mistral e mais! Open-source (MIT).
# AutoLearnAI

[![Licença: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Hugging Face Spaces](https://img.shields.io/badge/Hugging%20Face-Spaces-blue)](https://huggingface.co/spaces/seu-nome/autolearnai)

**AutoLearnAI**: IA grátis e segura que lê arquivos de Terabox, MEGA, Drive ou PC (PDF, ZIP, VHDL). Colabore em uma biblioteca compartilhada, pergunte e aprenda com buscas na web. Criptografia E2EE, anti-hackers e logs de erros. Escolha Llama 3, Mistral e mais! Open-source (MIT).

---

## Sobre o Projeto

Imagine um assistente de IA que não só responde suas perguntas, mas também aprende com arquivos que você e outros compartilham, tudo com segurança máxima! **AutoLearnAI** é isso: um chat simples que processa arquivos de **Terabox**, **MEGA**, **Google Drive** ou seu computador, responde perguntas (ex.: "Como programar um STM32?") e cresce com a comunidade. É gratuito, criptografado, protegido contra hackers e registra erros para facilitar correções.

Feito para todos – de iniciantes a experts – com interface amigável e código aberto. 🚀

---

## Funcionalidades

- **Upload Universal**: Envie arquivos de:
  - **Terabox**, **MEGA**, **Google Drive** (links diretos).
  - **Computador** (qualquer formato: `.pdf`, `.zip`, `.vhd`, `.txt`, `.docx`, `.pptx`, etc.).
- **Colaboração Global**: Arquivos formam uma biblioteca compartilhada, ajudando todos, com dados anonimizados.
- **Autoalimentação**: Se faltar informação, busca na web, aprende e salva para o futuro.
- **Múltiplas IAs**: Escolha entre:
  - Llama 3, Mistral 7B, Grok, Gemma 2, CodeLlama, DeepSeek, Falcon 7B, Qwen 2, Phi-3.
  - Todas gratuitas, rodando na nuvem.
- **Segurança Máxima**:
  - **Criptografia E2EE**: Arquivos e perguntas protegidos com AES-256.
  - **Anti-Hackers**: Validação de arquivos/links, sanitização de entradas, isolamento.
  - **Dispositivos Seguros**: Processamento na nuvem, sem risco ao PC.
- **Detecção de Erros**: Problemas salvos em `data/errors.log` para fácil diagnóstico.
- **Organização**: Inclui `.gitignore` para manter o repositório limpo (ignora `data/`, `__pycache__`, etc.).
- **Leigo-Friendly**: Interface web como um chat de WhatsApp.
- **Gratuito**: Usa Google Colab e Hugging Face Spaces, sem custo.

---

## Como Usar

### Online
1. Acesse: [AutoLearnAI no Hugging Face](https://huggingface.co/spaces/seu-nome/autolearnai) *(atualize com seu link)*.
2. Escolha a fonte: **Terabox**, **MEGA**, **Google Drive** ou **Computador**.
3. Cole links ou faça upload (máximo 100MB por arquivo, criptografado automaticamente).
4. Selecione uma IA (ex.: Mistral 7B).
5. Pergunte: "O que tem no meu PDF?" ou "Como aprender VHDL?".
6. Seus arquivos e perguntas ajudam a comunidade!

### Local
Quer rodar no seu PC? Siga:

```bash
# Clone o repositório
git clone https://github.com/seu-nome/AutoLearnAI
cd AutoLearnAI

# Instale dependências
pip install -r requirements.txt

# Inicie
streamlit run app.py

# AutoLearnAI

[![Licença: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Hugging Face Spaces](https://img.shields.io/badge/Hugging%20Face-Spaces-blue)](https://huggingface.co/spaces/linkmarlon/autolearnai)

**AutoLearnAI**: IA grátis que lê **qualquer arquivo** de Terabox, MEGA, Google Drive, Google Docs ou PC (PDF, VHDL, ZIP, etc.). Processa pastas inteiras, colabora globalmente, e responde perguntas com buscas na web. Criptografia E2EE, proteção anti-hackers, e logs de erros. Escolha Llama 3, Mistral e mais! Open-source (MIT).

---

## Sobre o Projeto

**AutoLearnAI** é um assistente de IA que processa **qualquer arquivo ou pasta** que humanos podem acessar – de códigos VHDL a documentos Google Docs. Envie links ou arquivos, pergunte (ex.: "Explique meu .vhd"), e contribua para uma biblioteca compartilhada. Seguro, gratuito, e tão fácil quanto um chat!

---

## Funcionalidades

- **Upload Universal**:
  - Links ou pastas de **Terabox**, **MEGA**, **Google Drive**, **Google Docs**.
  - Arquivos locais (**qualquer formato**: PDF, VHDL, TXT, ZIP, etc.).
- **Colaboração**: Dados anonimizados enriquecem a biblioteca global.
- **Autoalimentação**: Busca na web para respostas completas.
- **Múltiplas IAs**: Llama 3, Mistral 7B, Grok, Gemma 2, CodeLlama, DeepSeek, Falcon 7B, Qwen 2, Phi-3.
- **Segurança**:
  - Criptografia E2EE (AES-256).
  - Bloqueia apenas arquivos maliciosos (.exe, .bat).
  - Sanitização e isolamento.
- **Logs**: Erros detalhados em `data/errors.log`.
- **Organização**: `.gitignore` mantém o repositório limpo.

---

## Como Usar

### Online
1. Acesse: [AutoLearnAI no Hugging Face](https://huggingface.co/spaces/linkmarlon/autolearnai).
2. Escolha: **Terabox**, **MEGA**, **Google Drive**, **Google Docs** ou **Computador**.
3. Cole links (arquivos ou pastas) ou faça upload.
4. Selecione uma IA (ex.: Mistral 7B).
5. Pergunte: "O que tem no meu .vhd?" ou "Resuma esta pasta".
6. Seus dados ajudam a comunidade!

### Local
```bash
git clone https://github.com/linkmarlon/AutoLearnAI
cd AutoLearnAI
pip install -r requirements.txt
streamlit run app.py
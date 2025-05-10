# 🔐 Descriptografador Multiuso

Ferramenta escrita em Python para auxiliar profissionais e entusiastas de Segurança da Informação em tarefas de decodificação, análise e descriptografia de dados.

Desenvolvido para fins educacionais, este script oferece suporte a diversos tipos de codificação e algoritmos de criptografia, além de ataques simples como brute-force em cifras clássicas.

---

## 🧠 Funcionalidades

- 🔓 **Base64, Base16, Base10, Hexadecimal**
- 🧮 **Criptografia e descriptografia AES (modo EAX)**
- 💥 **Brute-force de XOR com chave de 1 byte**
- 🔁 **Brute-force da Cifra de César (ROT1 a ROT25)**
- 🔍 **Detecção automática de codificações comuns**
- 🧮 **Conversão de números inteiros longos em texto (CTF-style)**
- 🧩 **Resolução de desafio de XOR encadeado com múltiplas chaves**
- 🔑 **Hashing com MD5 e SHA-256**
- 📎 **Conversões entre formatos (string ↔ hex, etc)**

---

## 📦 Requisitos

- Python 3.6+
- Instale as dependências com:

```bash
pip install pycryptodome

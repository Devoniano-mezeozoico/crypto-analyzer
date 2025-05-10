import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.number import *
import os
from binascii import unhexlify

# Função XOR simples para 1 byte

def xor_decrypt(data, key):
    return bytes([byte ^ key for byte in data])

# Função XOR entre dois blocos

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

# Função para decodificar Base64
def decode_base64(data):
    try:
        decoded_data = base64.b64decode(data)
        return decoded_data
    except Exception as e:
        print(f"Erro ao decodificar Base64: {e}")
        return None

# Função para fazer hash MD5
def md5_hash(data):
    return hashlib.md5(data.encode()).hexdigest()

# Função para fazer hash SHA-256
def sha256_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

# Função para aplicar Cifra de César brute-force
def caesar_brute_force(data):
    print("\nTentando todas as 26 variações da Cifra de César:")
    for shift in range(1, 26):
        result = []
        for char in data:
            if 'a' <= char <= 'z':
                result.append(chr(((ord(char) - ord('a') + shift) % 26) + ord('a')))
            elif 'A' <= char <= 'Z':
                result.append(chr(((ord(char) - ord('A') + shift) % 26) + ord('A')))
            else:
                result.append(char)
        print(f"Deslocamento {shift:02d}: {''.join(result)}")

# Função para converter hexadecimal para string
def hex_to_string(hex_string):
    try:
        decoded_data = bytes.fromhex(hex_string)
        return decoded_data.decode()
    except Exception as e:
        print(f"Erro ao converter hexadecimal: {e}")
        return None

# Função para converter string para hexadecimal
def string_to_hex(data):
    return data.encode().hex()

# Função para criptografar com AES
def aes_encrypt(data, key):
    key = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return base64.b64encode(nonce + ciphertext).decode()

# Função para descriptografar AES
def aes_decrypt(data, key):
    try:
        if not key or len(key) < 4:
            print("Chave muito curta para AES. Use pelo menos 4 caracteres.")
            return None
        key = hashlib.sha256(key.encode()).digest()
        data = base64.b64decode(data)
        nonce = data[:16]
        ciphertext = data[16:]
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext.decode()
    except Exception as e:
        print(f"Erro ao descriptografar AES: {e}")
        return None

# Função para base16, base10 e base64 a partir de uma string hexadecimal
def convert_hex_to_base():
    hex_string = input("Digite a string hexadecimal: ")
    data_bytes = bytes.fromhex(hex_string)
    print(f"Base64: {base64.b64encode(data_bytes).decode()}")
    print(f"Base16: 0x{data_bytes.hex()}")
    print(f"Base10: {int.from_bytes(data_bytes, byteorder='big')}")

# Função para converter long int em texto usando PyCryptodome
def long_to_text():
    n = int(input("Digite o número inteiro longo: "))
    print(f"Texto recuperado: {long_to_bytes(n).decode()}")

# XOR string com brute-force de uma chave de 1 byte
def xor_brute_force():
    hex_string = input("Digite a string hexadecimal codificada com XOR de 1 byte: ")
    cipher = unhexlify(hex_string)
    for key in range(256):
        result = bytes([b ^ key for b in cipher])
        try:
            decoded = result.decode()
            if decoded.startswith("crypto"):
                print(f"Chave: {key} -> Mensagem: {decoded}")
        except:
            continue

# Desafio com múltiplas XORs encadeadas
def xor_multiple_keys():
    KEY1 = bytes.fromhex("a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313")
    KEY2_xor_KEY1 = bytes.fromhex("37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e")
    KEY2 = xor_bytes(KEY2_xor_KEY1, KEY1)
    KEY3_xor_KEY2 = bytes.fromhex("c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1")
    KEY3 = xor_bytes(KEY3_xor_KEY2, KEY2)
    FLAG_xor_ALL = bytes.fromhex("04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf")
    FULL_KEY = xor_bytes(xor_bytes(KEY1, KEY2), KEY3)
    FLAG = xor_bytes(FLAG_xor_ALL, FULL_KEY)
    print(f"FLAG: {FLAG.decode()}")

# Detecção automática de codificação comum
def auto_detect(data):
    try:
        decoded = base64.b64decode(data).decode()
        print(f"Possível Base64: {decoded}")
    except: pass
    try:
        decoded = bytes.fromhex(data).decode()
        print(f"Possível Hex: {decoded}")
    except: pass

def decrypt(data, cipher_type, key=None):
    if cipher_type == 'base64':
        print(f"Decodificando Base64: {data}")
        decoded_data = decode_base64(data)
        if decoded_data is not None:
            print(f"Decodificado: {decoded_data.decode(errors='ignore')}")
        else:
            print("Não foi possível decodificar a string Base64.")

    elif cipher_type == 'xor':
        print(f"Aplicando XOR com a chave {key}: {data}")
        decoded_data = decode_base64(data)
        if decoded_data:
            decoded_data = xor_decrypt(decoded_data, key)
            print(f"Resultado após XOR: {decoded_data.decode(errors='ignore')}")

    elif cipher_type == 'md5':
        print(f"Calculando MD5 para: {data}")
        hashed = md5_hash(data)
        print(f"Hash MD5: {hashed}")

    elif cipher_type == 'sha256':
        print(f"Calculando SHA-256 para: {data}")
        hashed = sha256_hash(data)
        print(f"Hash SHA-256: {hashed}")

    elif cipher_type == 'rot13':
        print(f"Aplicando brute-force da Cifra de César (ROT1-ROT25): {data}")
        caesar_brute_force(data)

    elif cipher_type == 'hex':
        print(f"Convertendo de Hexadecimal para texto: {data}")
        decoded_data = hex_to_string(data)
        if decoded_data:
            print(f"Texto convertido: {decoded_data}")
        else:
            print("Falha na conversão.")

    elif cipher_type == 'aes':
        print(f"Descriptografando AES: {data}")
        decrypted_data = aes_decrypt(data, key)
        if decrypted_data:
            print(f"Texto descriptografado: {decrypted_data}")
        else:
            print("Falha na descriptografia.")

    elif cipher_type == 'auto':
        print(f"Tentando detectar codificação de: {data}")
        auto_detect(data)

    else:
        print("Tipo de criptografia não reconhecido.")

def main():
    print("\nEscolha o tipo de operação:")
    print("1. Decodificar Base64")
    print("2. XOR (com chave)")
    print("3. MD5")
    print("4. SHA-256")
    print("5. Cifra de César (brute-force)")
    print("6. Hexadecimal")
    print("7. AES")
    print("8. Converter Hex para Base16/Base64/Base10")
    print("9. Converter número longo para texto")
    print("10. XOR brute-force com 1 byte")
    print("11. Desafio XOR com múltiplas chaves")
    print("12. Auto detectar encoding")

    choice = input("Escolha uma opção (1-12): ")

    if choice in [str(i) for i in range(1, 8)]:
        data = input("Digite a string criptografada: ")
        if choice == '1':
            decrypt(data, 'base64')
        elif choice == '2':
            key = int(input("Digite a chave XOR: "))
            decrypt(data, 'xor', key)
        elif choice == '3':
            decrypt(data, 'md5')
        elif choice == '4':
            decrypt(data, 'sha256')
        elif choice == '5':
            decrypt(data, 'rot13')
        elif choice == '6':
            print("1. Converter de Hexadecimal para texto")
            print("2. Converter de texto para Hexadecimal")
            hex_choice = input("Escolha uma opção (1-2): ")
            if hex_choice == '1':
                decrypt(data, 'hex')
            elif hex_choice == '2':
                print(f"Texto em Hexadecimal: {string_to_hex(data)}")
        elif choice == '7':
            key = input("Digite a chave AES: ")
            decrypt(data, 'aes', key)

    elif choice == '8':
        convert_hex_to_base()
    elif choice == '9':
        long_to_text()
    elif choice == '10':
        xor_brute_force()
    elif choice == '11':
        xor_multiple_keys()
    elif choice == '12':
        data = input("Digite a string a ser analisada: ")
        decrypt(data, 'auto')
    else:
        print("Opção inválida.")

if __name__ == "__main__":
    while True:
        main()
        cont = input("\nDeseja continuar? (s/n): ").lower()
        if cont != 's':
            break

import os
import time
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import matplotlib.pyplot as plt



arquivo_conteudo = open("./texto-gerado.txt", "rb")
arquivo_criptado_conteudo = "./arquivo-criptado-rsa.txt"


def encrypt_rsa(file_path):
    # Generate RSA keys
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    # Encrypt the file
    
    line =  arquivo_conteudo.readline()
    encrypted_data = bytes()
    while line:
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
        encrypted_data += cipher_rsa.encrypt(line)
        # Save the encrypted file
        line = arquivo_conteudo.readline()
    print("saindo da leitura")
    with open(arquivo_criptado_conteudo, 'wb') as file:
        file.write(encrypted_data)

    return private_key, arquivo_criptado_conteudo

def encrypt_aes(file_path):
    # Generate AES key
    key = get_random_bytes(32)

    # Encrypt the file
    with open("./texto-gerado.txt", 'rb') as file:
        data = file.read()

    cipher_aes = AES.new(key, AES.MODE_EAX)
    encrypted_data, tag = cipher_aes.encrypt_and_digest(data)

    # Save the encrypted file
    encrypted_file_path = file_path + ".encrypted_aes"
    with open(encrypted_file_path, 'wb') as file:
        [file.write(x) for x in (cipher_aes.nonce, tag, encrypted_data)]

    return key, encrypted_file_path


def decrypt_rsa(private_key, encrypted_file_path):
    # Decrypt the file using RSA private key
    arquivo_conteudo = open(encrypted_file_path, "rb")
    decrypted_data = b""
    chunk_size = 256  # Tamanho do bloco de descriptografia

    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
    line = arquivo_conteudo.read(chunk_size).strip(b"\n")

    while line:
        decrypted_chunk = cipher_rsa.decrypt(line)
        decrypted_data += decrypted_chunk
        line = arquivo_conteudo.read(chunk_size)

    arquivo_conteudo.close()

    decrypted_file_path = encrypted_file_path + ".decrypted_rsa.txt"
    with open(decrypted_file_path, 'wb') as file:
        file.write(decrypted_data)

    return decrypted_file_path


def decrypt_aes(key, encrypted_file_path):
    # Decrypt the file using AES key
    with open(encrypted_file_path, 'rb') as file:
        nonce, tag, encrypted_data = [file.read(x) for x in (16, 16, -1)]

    cipher_aes = AES.new(key, AES.MODE_EAX, nonce)
    decrypted_data = cipher_aes.decrypt_and_verify(encrypted_data, tag)

    # Save the decrypted file
    decrypted_file_path = encrypted_file_path + ".decrypted_aes"
    with open(decrypted_file_path, 'wb') as file:
        file.write(decrypted_data)

    return decrypted_file_path


def main():
    file_path = "./texto-gerado.txt"

    try:
        # Check if the file exists
        if not os.path.isfile(file_path):
            raise FileNotFoundError("File not found.")

        # Encrypt using RSA
        start_time = time.time()
        private_key, encrypted_file_path_rsa = encrypt_rsa(file_path)
        rsa_encryption_time = time.time() - start_time

        # Encrypt using AES
        start_time = time.time()
        key, encrypted_file_path_aes = encrypt_aes(file_path)
        aes_encryption_time = time.time() - start_time

        # Decrypt using RSA
        start_time = time.time()
        decrypted_file_path_rsa = decrypt_rsa(private_key, encrypted_file_path_rsa)
        rsa_decryption_time = time.time() - start_time

        # Decrypt using AES
        start_time = time.time()
        decrypted_file_path_aes = decrypt_aes(key, encrypted_file_path_aes)
        aes_decryption_time = time.time() - start_time

        print("Encryption time (RSA):", rsa_encryption_time)
        print("Encryption time (AES):", aes_encryption_time)
        print("Decryption time (RSA):", rsa_decryption_time)
        print("Decryption time (AES):", aes_decryption_time)
        tempos_aes = [aes_encryption_time, aes_decryption_time]  # Tempos de criptografia e descriptografia do AES
        tempos_rsa = [rsa_encryption_time, rsa_decryption_time]    # Tempos de criptografia e descriptografia do RSA

        # Rótulos para o eixo x

        # Tempos de encriptação e descriptação (em segundos)
        tempos_encriptacao = [aes_encryption_time,rsa_encryption_time]  # Tempos de encriptação (AES, RSA, Outro)
        tempos_descriptacao = [aes_decryption_time,rsa_decryption_time]  # Tempos de descriptação (AES, RSA, Outro)

        # Rótulos dos métodos
        metodos = ['AES', 'RSA']

        # Gráfico de encriptação
        plt.subplot(2, 1, 1)
        plt.bar(metodos, tempos_encriptacao)
        plt.xlabel('Método')
        plt.ylabel('Encriptação (s)')
        plt.title('Tempos de Encriptação')

        # Gráfico de descriptação
        plt.subplot(2, 1, 2)
        plt.bar(metodos, tempos_descriptacao)
        plt.xlabel('Método')
        plt.ylabel('Descriptação (s)')
        plt.title('Tempos de Descriptação')

        # Ajusta o espaçamento entre os subplots
        plt.subplots_adjust(hspace=0.5)

        # Exibe os gráficos
        plt.show()

    except Exception as e:
        print("An error occurred:", str(e))


if __name__ == '__main__':
    main()

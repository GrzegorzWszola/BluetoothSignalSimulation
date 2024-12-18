import random
from commpy.channelcoding import Trellis, conv_encode, viterbi_decode
import numpy as np
from bitstring import BitArray
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
from bitarray import bitarray

# Działanie funkcji
# 1. Obliczanie CRC: Funkcja calculate_crc_bluetooth jest wywoływana, aby obliczyć wartość CRC dla odebranych danych.
# 2. Porównanie CRC: Obliczone CRC jest porównywane z dołączonym do danych received_crc. Jeśli się zgadzają, to dane są prawidłowe; jeśli nie, oznacza to, że wystąpił błąd podczas transmisji.
#
# Uwagi
# Odebrany CRC powinien być częścią pakietu danych, a nie samymi danymi do obliczenia CRC. Zwykle podczas odbioru oddzielamy dane i dołączone CRC.
# Funkcja działa dla 24-bitowego CRC-24 używanego w Bluetooth i jest ogólnie stosowana w weryfikacji poprawności pakietów danych, umożliwiając detekcję błędów.
def calculate_crc(data, polynomial: int = 0x864CFB, initial_value: int = 0x555555) -> int:
    crc = initial_value

    for byte in data:
        crc ^= byte << 16  # XOR-uje bajt z górnymi 8 bitami CRC
        for _ in range(8):  # Przetwarza każdy bit
            if crc & 0x800000:  # Jeśli najbardziej znaczący bit jest ustawiony
                crc = (crc << 1) ^ polynomial
            else:
                crc <<= 1
            crc &= 0xFFFFFF  # Upewnia się, że CRC pozostaje 24-bitowe
    return crc

# Działanie funkcji
# 1. Inicjalizacja LFSR: Rejestr LFSR jest ustawiany na wartość channel | 0x80, gdzie najstarszy bit jest ustawiony na 1 (pozycja 7) dla maski początkowej.
# 2. Pętla bajtów i bitów:
# Każdy bajt w danych jest przetwarzany po jednym bicie na raz.
# Dla każdego bitu maska wybielająca (whitening_bit) jest XOR-owana z danymi.
# LFSR jest przesuwany i aktualizowany zgodnie z wielomianem x^7 + x^4 + 1.
# 3. Aktualizacja LFSR: Rejestr LFSR przesuwa się o 1 bit i jest aktualizowany na podstawie nowego bitu, wynikającego z wielomianu. Operacja AND 0x7F zapewnia, że LFSR zachowuje tylko 7 bitów.
#
# Uwagi:
# Kanał: Ponieważ maska wybielająca zależy od numeru kanału, wyniki wybielania będą różne dla różnych kanałów, co pomaga w rozróżnianiu transmisji na różnych kanałach.
# Odwrotne wybielanie: Proces odwrotny do wybielania działa identycznie, więc ponowne zastosowanie tej funkcji do wybielonych danych (z tym samym kanałem) przywróci oryginalne dane.
def whitening_bluetooth(data, channel: int) -> bytes:
    # Inicjalizacja LFSR numerem kanału (7-bitowy LFSR)
    lfsr = channel | 0x80  # Wartość początkowa LFSR z ustawionym najstarszym bitem

    whitened_data = bytearray()

    for byte in data:
        whitened_byte = byte
        for bit in range(8):
            # Pobiera bit maski wybielającej
            whitening_bit = lfsr & 0x01

            # XOR z aktualnym bitem danych
            whitened_byte ^= (whitening_bit << (7 - bit))

            # Aktualizacja LFSR z wielomianem x^7 + x^4 + 1
            new_bit = ((lfsr >> 6) ^ (lfsr >> 3)) & 0x01
            lfsr = ((lfsr << 1) | new_bit) & 0x7F  # Zachowanie tylko 7 bitów
        whitened_data.append(whitened_byte)
    return bytes(whitened_data)

def fec_encoding(data) -> bytes:
    trellis = Trellis(np.array([3]), g_matrix=np.array([[0o15, 0o13]]))
    byte_array = np.frombuffer(data, dtype=np.uint8)
    new_data = np.unpackbits(byte_array)
    return np.packbits(conv_encode(new_data, trellis)).tobytes()

def fec_decoding(data) -> bytes:
    trellis = Trellis(np.array([3]), g_matrix=np.array([[0o15, 0o13]]))
    byte_array = np.frombuffer(data, dtype=np.uint8)
    new_data = np.unpackbits(byte_array)
    decodedData = viterbi_decode(new_data, trellis)
    return np.packbits(decodedData).tobytes().rstrip(b'\x00')

def aes_ccm_encrypt(plaintext, crc, key, nonce):
    aes_ccm = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())

    encryptor = aes_ccm.encryptor()
    encryptor.authenticate_additional_data(bytes(crc))  # Optional associated data for authentication
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    return ciphertext, tag

def aes_gcm_decrypt(ciphertext, crc, key, nonce, tag) -> bytes:
    try:
        # Initialize the cipher with AES-GCM mode and the tag
        aes_gcm = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = aes_gcm.decryptor()
        decryptor.authenticate_additional_data(bytes(crc))

        # Decrypt the data
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_data

    except Exception as e:
        print(f"Decryption failed: {e}")
        return None

def simulate_bit_flip(bitarray, i) -> bytes:
    for bit in range(0, i):
        index_to_flip = random.randint(0, len(bitarray) - 1)

        bitarray[index_to_flip] = not bitarray[index_to_flip]

    return bytes(bitarray)

# # Przykład użycia
# dataInput = bytes(BitArray(bin='0010010011101100011101100111')) # Przykładowe dane
# channel = 1000  # Przykładowy kanał dla Bluetooth LE
# aad = b'additional data'
# key = os.urandom(16)  #16 bajtów - 128 bitów losowany klucz do encryptowania
# print(f"AES Key: {key.hex()}")
# nonce = os.urandom(13)  # Nonce (unique for each encryption session) Bluetooth używa 13 bajtowego
# print(f"Nonce: {nonce.hex()}")
#
# print(f"Dane:  {BitArray(dataInput).bin}")
#
# dataEncrypted, tag = aes_ccm_encrypt(dataInput, aad, key, nonce)
# print(f"Enkryptowane: {BitArray(dataEncrypted).bin}")
#
# dataCRC = calculate_crc(dataEncrypted, channel)
#
# dataWhitened = whitening_bluetooth(dataEncrypted, channel)
# print(f"Dane po wybieleniu: {BitArray(dataWhitened).bin}")
#
# dataEncoded = fec_encoding(dataWhitened)
# print(f"Dabe zakodowane: {BitArray(dataEncoded).bin}")
#
# inteferedCode = simulate_bit_flip(BitArray(dataEncoded), 8)
# print(f"InterferedCode: {BitArray(inteferedCode).bin}")
#
# dataDecoded = fec_decoding(inteferedCode)
# print(f"Dane zdekodowane: {BitArray(dataDecoded).bin}")
#
# dataDewhitened = whitening_bluetooth(dataDecoded, channel)
# print(f"Dane odbielone: {BitArray(dataDewhitened).bin}")
#
# dataCRC2 = calculate_crc(dataDewhitened, channel)
# if dataCRC == dataCRC2:
#     print("good CRC")
# else:
#     print("bad CRC")
#
# dataDecrypted = aes_gcm_decrypt(dataDewhitened, aad, key, nonce, tag)
# print(f"Dane dekryptowane: {BitArray(dataDecrypted).bin}")

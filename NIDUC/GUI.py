import os
import tkinter as tk
from tkinter import ttk

from bitstring import BitArray
import Backend
from Backend import calculate_crc

root = tk.Tk()
root.title("Bluetooth simulation")
root.geometry("800x600")
root.config(background="white")

# Function to reset everything
def reset_all():
    entry.delete(0, tk.END)  # Clear the Entry widget

    # Reset the StringVar variables
    dataBinaryVar.set("Binary representation: ")
    dataEncryptedVar.set("Encrypted data: ")
    dataCRC.set("Calculated CRC: ")
    dataWhitenedVar.set("Data whitened: ")
    dataEncodedVar.set("Data encoded: ")
    dataInterferedVar.set("Data after interference: ")
    dataDecodedVar.set("Data after interference: ")
    dataDewhitenedVar.set("Data Dewhitened: ")
    dataCRC2.set("CRC2: ")
    dataDecryptedVar.set("Decrypted data: ")
    finalString.set("Final String: ")

# Function to generate new data and perform encryption/decryption
def generate_new():
    data_input = entry.get().encode('utf-8')
    channel = 1000
    aad = b'additional data'
    key = os.urandom(16)
    nonce = os.urandom(13)
    dataBinaryVar.set(f"Binary representation: {BitArray(data_input).bin}")
    data_encrypted, tag = Backend.aes_ccm_encrypt(data_input, aad, key, nonce)
    dataEncryptedVar.set(f"Encrypted data: {BitArray(data_encrypted).bin}")
    data_crc = calculate_crc(data_encrypted, channel)
    dataCRC.set(f"Calculated CRC: {data_crc}")
    data_whitened = Backend.whitening_bluetooth(data_encrypted, channel)
    dataWhitenedVar.set(f"Whitened data: {BitArray(data_whitened).bin}")
    data_encoded = Backend.fec_encoding(data_whitened)
    dataEncodedVar.set(f"Encoded data: {BitArray(data_encoded).bin}")
    data_interfered = Backend.simulate_bit_flip(BitArray(data_encoded), 5)
    dataInterferedVar.set(f"Interfered data: {BitArray(data_interfered).bin}")
    data_decoded = Backend.fec_decoding(data_interfered)
    dataDecodedVar.set(f"Decoded data: {BitArray(data_decoded).bin}")
    data_dewhitened = Backend.whitening_bluetooth(data_decoded, channel)
    dataDewhitenedVar.set(f"Dewhitened data: {BitArray(data_dewhitened).bin}")
    data_crc2 = calculate_crc(data_dewhitened, channel)
    if(data_crc == data_crc2):
        dataCRC2.set(f"Calculated CRC is okay: {data_crc2} = {data_crc}")
        data_decrypted = Backend.aes_gcm_decrypt(data_dewhitened, aad, key, nonce, tag)
        dataDecryptedVar.set(f"Decrypted data: {BitArray(data_decrypted).bin}")
        finalString.set("Final string: " + data_decrypted.decode('utf-8'))
    else:
        dataCRC2.set(f"Calculated CRC is not okay: {data_crc2} != {data_crc}")

def to_hex():
    data_input = entry.get().encode('utf-8')
    channel = 1000
    aad = b'additional data'
    key = os.urandom(16)
    nonce = os.urandom(13)
    dataBinaryVar.set(f"Binary representation: {data_input.hex()}")
    data_encrypted, tag = Backend.aes_ccm_encrypt(data_input, aad, key, nonce)
    dataEncryptedVar.set(f"Encrypted data: {data_encrypted.hex()}")
    data_crc = calculate_crc(data_encrypted, channel)
    dataCRC.set(f"Calculated CRC: {data_crc}")
    data_whitened = Backend.whitening_bluetooth(data_encrypted, channel)
    dataWhitenedVar.set(f"Whitened data: {data_whitened.hex()}")
    data_encoded = Backend.fec_encoding(data_whitened)
    dataEncodedVar.set(f"Encoded data: {data_encoded.hex()}")
    data_interfered = Backend.simulate_bit_flip(BitArray(data_encoded), 5)
    dataInterferedVar.set(f"Interfered data: {data_interfered.hex()}")
    data_decoded = Backend.fec_decoding(data_interfered)
    dataDecodedVar.set(f"Decoded data: {data_decoded.hex()}")
    data_dewhitened = Backend.whitening_bluetooth(data_decoded, channel)
    dataDewhitenedVar.set(f"Dewhitened data: {data_dewhitened.hex()}")
    data_crc2 = calculate_crc(data_dewhitened, channel)
    if(data_crc == data_crc2):
        dataCRC2.set(f"Calculated CRC is okay: {data_crc2} = {data_crc}")
        data_decrypted = Backend.aes_gcm_decrypt(data_dewhitened, aad, key, nonce, tag)
        dataDecryptedVar.set(f"Decrypted data: {data_decrypted.hex()}")
        finalString.set("Final string: " + data_decrypted.decode('utf-8'))
    else:
        dataCRC2.set(f"Calculated CRC is not okay: {data_crc2} != {data_crc}")


canvas = tk.Canvas(root, bg="white")
canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

scrollbar = tk.Scrollbar(root, orient="vertical", command=canvas.yview)
scrollbar.pack(side=tk.RIGHT, fill="y")

canvas.configure(yscrollcommand=scrollbar.set)

scrollable_frame = tk.Frame(canvas, bg="white")

canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")

# Bind the frame resizing to the canvas scrolling
scrollable_frame.bind(
    "<Configure>",
    lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
)

# Creating the UI components inside the scrollable frame
label = tk.Label(scrollable_frame, text="Text to send:", background="white", fg="#0082FC", font=("Roboto", 16, "bold"))
label.grid(column=0, row=0, padx=5, pady=5)
entry = tk.Entry(scrollable_frame, font=("Roboto", 14, "bold"))
entry.grid(column=1, row=0, padx=5, pady=5)
submit_button = tk.Button(scrollable_frame, text="Submit", font=("Roboto", 9, "bold"), relief="flat", borderwidth=1, bg="#0082FC", fg="white", command=generate_new)
submit_button.grid(column=2, row=0, padx=5, pady=5)
reset_button = tk.Button(scrollable_frame, text="Reset", font=("Roboto", 9, "bold"), relief="flat", borderwidth=1, bg="#FC4200", fg="white", command=reset_all)
reset_button.grid(column=3, row=0, padx=5, pady=5)
to_hex_button = tk.Button(scrollable_frame, text="Swap to hex", font=("Roboto", 9, "bold"), relief="flat", borderwidth=1, bg="green", fg="white", command=to_hex)
to_hex_button.grid(column=4, row=0, padx=5, pady=5)
to_bin_button = tk.Button(scrollable_frame, text="Swap to bin", font=("Roboto", 9, "bold"), relief="flat", borderwidth=1, bg="green", fg="white", command=generate_new)
to_bin_button.grid(column=5, row=0, padx=5, pady=5)

dataBinaryVar = tk.StringVar()
dataBinaryVar.set("Binary representation: ")
labelDataBinary = tk.Label(scrollable_frame, textvariable=dataBinaryVar, font=("Roboto", 10, "bold"), bg="white", fg="black", wraplength=500, justify="left")
labelDataBinary.grid(column=0, row=2, pady=5, columnspan=4, sticky="W")

dataEncryptedVar = tk.StringVar()
dataEncryptedVar.set("Encrypted data: ")
labelDataEncrypted = tk.Label(scrollable_frame, textvariable=dataEncryptedVar, font=("Roboto", 10, "bold"), bg="white", fg="black", wraplength=500, justify="left")
labelDataEncrypted.grid(column=0, row=3, pady=5, columnspan=4, sticky="W")

dataCRC = tk.StringVar()
dataCRC.set("Calculated CRC: ")
labelCalculatedCRC = tk.Label(scrollable_frame, textvariable=dataCRC, font=("Roboto", 10, "bold"), bg="white", fg="black", wraplength=500, justify="left")
labelCalculatedCRC.grid(column=0, row=4, pady=5, columnspan=4, sticky="W")

dataWhitenedVar = tk.StringVar()
dataWhitenedVar.set("Data whitened: ")
labelDataWhitened = tk.Label(scrollable_frame, textvariable=dataWhitenedVar, font=("Roboto", 10, "bold"), bg="white", fg="black", wraplength=500, justify="left")
labelDataWhitened.grid(column=0, row=5, pady=5, columnspan=4, sticky="W")

dataEncodedVar = tk.StringVar()
dataEncodedVar.set("Data encoded: ")
labelDataEncoded = tk.Label(scrollable_frame, textvariable=dataEncodedVar, font=("Roboto", 10, "bold"), bg="white", fg="black", wraplength=500, justify="left")
labelDataEncoded.grid(column=0, row=6, pady=5, columnspan=4, sticky="W")

dataInterferedVar = tk.StringVar()
dataInterferedVar.set("Data after interference: ")
labelDataInterfered = tk.Label(scrollable_frame, textvariable=dataInterferedVar, font=("Roboto", 10, "bold"), bg="white", fg="black", wraplength=500, justify="left")
labelDataInterfered.grid(column=0, row=7, pady=5, columnspan=4, sticky="W")

dataDecodedVar = tk.StringVar()
dataDecodedVar.set("Data after interference: ")
labelDataDecoder = tk.Label(scrollable_frame, textvariable=dataDecodedVar, font=("Roboto", 10, "bold"), bg="white", fg="black", wraplength=500, justify="left")
labelDataDecoder.grid(column=0, row=8, pady=5, columnspan=4, sticky="W")

dataDewhitenedVar = tk.StringVar()
dataDewhitenedVar.set("Data Dewhitened: ")
labelDataDewhitened = tk.Label(scrollable_frame, textvariable=dataDewhitenedVar, font=("Roboto", 10, "bold"), bg="white", fg="black", wraplength=500, justify="left")
labelDataDewhitened.grid(column=0, row=9, pady=5, columnspan=4, sticky="W")

dataCRC2 = tk.StringVar()
dataCRC2.set("CRC2: ")
labelCRC2 = tk.Label(scrollable_frame, textvariable=dataCRC2, font=("Roboto", 10, "bold"), bg="white", fg="black", wraplength=500, justify="left")
labelCRC2.grid(column=0, row=10, pady=5, columnspan=4, sticky="W")

dataDecryptedVar = tk.StringVar()
dataDecryptedVar.set("Decrypted data: ")
labelDecryptedData = tk.Label(scrollable_frame, textvariable=dataDecryptedVar, font=("Roboto", 10, "bold"), bg="white", fg="black", wraplength=500, justify="left")
labelDecryptedData.grid(column=0, row=11, pady=5, columnspan=4, sticky="W")

finalString = tk.StringVar()
finalString.set("Final string: ")
labelFinalString = tk.Label(scrollable_frame, textvariable=finalString, font=("Roboto", 10, "bold"), bg="white", fg="black", wraplength=500, justify="left")
labelFinalString.grid(column=0, row=11, pady=5, columnspan=4, sticky="W")


root.mainloop()

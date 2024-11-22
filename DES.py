import tkinter as tk
from tkinter import filedialog
import fitz


PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

ShiftDetails = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# S-boxes
Sboxes = [
    # 1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    
    # 2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    
    # 3
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    
    # 4
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    
    # 5
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    
    # 6
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    
    # 7
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    
    # 8
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]
# Initial permutation table (IP)
InitialP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9,  1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

# Final permutation table (FP)
FinalP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25
]

# Expansion table (E)
ExpentionT = [
    32,  1,  2,  3,  4,  5,
    4,   5,  6,  7,  8,  9,
    8,   9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

# Permutation (P)
P = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26,  5, 18, 31, 10,
    2,  8, 24, 14, 32, 27,  3,  9,
    19, 13, 30, 6, 22, 11,  4, 25
]

# Binary to String Conversion
def binary_to_string(binary_text):
    chars = [binary_text[i:i+8] for i in range(0, len(binary_text), 8)]
    return ''.join(chr(int(char, 2)) for char in chars)

# String to Binary Conversion
def string_to_binary(text):
    binaryText = ''.join(format(ord(char), '08b') for char in text)
    return binaryText

#Binary to Hexadecimal Conversion
def binary_to_hex(binary_text):
    return hex(int(binary_text, 2))[2:]

#Hexadicimal to Binary Conversion
def hex_to_binary(hex_text):
    cleaned_hex = ''.join(hex_text.split())  
    try:
        binary_text = bin(int(cleaned_hex, 16))[2:]  # Conversion to binary
        
        while len(binary_text) % 4 != 0:
            binary_text = '0' + binary_text
        return binary_text
    except ValueError:
        raise ValueError(f"Invalid hexadecimal input: {cleaned_hex}")


# Key Scheduling Class
class KeyGenerator:
    def strToBin(self, InputKey):
        return string_to_binary(InputKey)

    def permute(self, bits, givenTable):
        binaryText=''
        for i in givenTable:
            binaryText+=bits[i-1]
        return binaryText
    
    def generate16keys(self, master64bitK):
        key56bit = self.permute(master64bitK, PC1)
        L, R = key56bit[:28], key56bit[28:]

        Roundkeys = []
        for NoOfShift in ShiftDetails:
            L = L[NoOfShift:] + L[:NoOfShift]
            R = R[NoOfShift:] + R[:NoOfShift]
            combineBoth = L + R
            roundKey = self.permute(combineBoth, PC2)
            Roundkeys.append(roundKey)
        return Roundkeys

# DES Class
class DES:
    def __init__(self, roundKeys):
        self.roundKeys = roundKeys

    def permute(self, bits, givenTable):
        binaryText=''
        for i in givenTable:
            binaryText+=bits[i-1]
        return binaryText
    
    def XOR(self, binaryArray1, binaryArray2):
        XorOutput=''
        for bit1, bit2 in zip(binaryArray1, binaryArray2):
            if bit1!=bit2:
                XorOutput+='1'
            else:
                XorOutput+='0'
        return XorOutput
    
    def sBoxSub(self, BitsInput):
        outputBlock = []
        for i in range(8):
            bits = BitsInput[i * 6:(i + 1) * 6]
            row = int(bits[0] + bits[5], 2)
            col = int(bits[1:5], 2)
            sBoxVal = Sboxes[i][row][col]
            outputBlock.append(format(sBoxVal, '04b'))
        return ''.join(outputBlock)

    #Feistel Function
    def festelFunc(self, rightHalf, roundKey):
        #Expand
        expandedR = self.permute(rightHalf, ExpentionT)
        #XOR
        XORed = self.XOR(expandedR, roundKey)
        #S Box Subsitution
        substituted = self.sBoxSub(XORed)
        #Return and permutation according to P-box
        return self.permute(substituted, P)

# DesEncryption Class inherit from DES
class DesEncryption(DES):
    def encryption(self, plainT):
        binaryText = string_to_binary(plainT)
        while len(binaryText) % 64 != 0:
            binaryText += '0'

        cipherT = ""
        for i in range(0, len(binaryText), 64):
            block = binaryText[i:i + 64]
            permutedB = self.permute(block, InitialP)
            L, R = permutedB[:32], permutedB[32:]

            for Key in self.roundKeys:
                newR = self.XOR(L, self.festelFunc(R, Key))
                L, R = R, newR

            combinedBoth = R + L
            finalp = self.permute(combinedBoth, FinalP)
            cipherT += finalp

        return binary_to_hex(cipherT)

# DesDecryption Class inherit from DES
class DESdecryption(DES):
    def decryption(self, hexCipherT):
        binaryText = hex_to_binary(hexCipherT)
        while len(binaryText) % 64 != 0:
            binaryText += '0'

        plainT = ""
        for i in range(0, len(binaryText), 64):
            block = binaryText[i:i + 64]
            permutedB = self.permute(block, InitialP)
            L, R = permutedB[:32], permutedB[32:]

            for Key in reversed(self.roundKeys):
                newR = self.XOR(L, self.festelFunc(R, Key))
                L, R = R, newR

            combinedBoth = R + L
            finalp = self.permute(combinedBoth, FinalP)
            plainT += finalp

        return binary_to_string(plainT)

# Save to PDF Function
def save_to_pdf(text, filename):
    doc = fitz.open()
    page = doc.new_page()
    lines = [text[i:i + 85] for i in range(0, len(text), 85)]
    # set initial value of curcer
    x, y = 50, 50
    #inserting line by line(line length is 64 char)
    for line in lines:
        page.insert_text((x, y), line)
        y += 25
        if y > 800:
            page = doc.new_page()
            y = 50

    doc.save(filename)
    doc.close()


# User Interface
def main():
    def select_file():
        file_path = filedialog.askopenfilename(title="Select a PDF File", filetypes=[("PDF Files", "*.pdf")])
        if file_path:
            file_label.config(text=f"Selected File: {file_path}")
            selected_file_path.set(file_path)

    #Show Guide text if something is missing
    def process_file():
        file_path = selected_file_path.get()
        if not file_path:
            result_label.config(text="No file selected!")
            return

        operation = operation_var.get()
        if operation not in ["Encrypt", "Decrypt"]:
            result_label.config(text="Please select an operation (Encrypt/Decrypt).")
            return

        with fitz.open(file_path) as doc:
            page = doc[0]
            text = page.get_text("text")

        #Perform Encryption and decryption according to radio button selection and save to corresponding file
        if operation == "Encrypt":
            desE = DesEncryption(roundKeys)
            processed_text = desE.encryption(text)
            output_file = "EncryptedFile.pdf"
        elif operation == "Decrypt":
            desD = DESdecryption(roundKeys)
            processed_text = desD.decryption(text)
            output_file = "DecryptedFile.pdf"

        save_to_pdf(processed_text, output_file)
        result_label.config(text=f"Operation successful! Saved to {output_file}")


    #User Interface componant
    root = tk.Tk()
    root.title("DES Encryption/Decryption Tool")
    selected_file_path = tk.StringVar()
    operation_var = tk.StringVar()

    tk.Label(root, text="DES Encryption/Decryption Tool", font=("Arial", 20)).pack(pady=30)
    file_label = tk.Label(root, text="No file selected.", font=("Arial", 16))
    file_label.pack(pady=5)

    tk.Button(root, text="Select File", command=select_file).pack(pady=20)

    tk.Label(root, text="Choose Operation:", font=("Arial", 12)).pack(pady=20)
    tk.Radiobutton(root, text="Encrypt", variable=operation_var, value="Encrypt").pack()
    tk.Radiobutton(root, text="Decrypt", variable=operation_var, value="Decrypt").pack()

    tk.Button(root, text="Process File", command=process_file).pack(pady=20)

    result_label = tk.Label(root, text="", font=("Arial", 16))
    result_label.pack(pady=10)

    root.mainloop()

# Key Generation and Running the UI
if __name__ == "__main__":
    key = 'UMAIRNAZ'
    keyGeneratorObj = KeyGenerator()
    master64bitK = keyGeneratorObj.strToBin(key)
    roundKeys = keyGeneratorObj.generate16keys(master64bitK)
    main()

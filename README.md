# Data-Encryption-Standard-DSA-

This project implements a Data Encryption Standard (DES)-based encryption and decryption tool for securing text in PDF files. The tool is designed as a user-friendly application with a graphical interface, built using Python and Tkinter. It facilitates secure handling of sensitive text by encrypting and decrypting content based on a 64-bit master key.

The core of the project involves the DES algorithm, which operates on blocks of data through 16 rounds of key-dependent transformations. The tool incorporates critical DES components, including initial and final permutations, round key generation, S-box substitutions, and Feistel structure processing. These ensure secure and reversible transformations for both encryption and decryption.

Users can select PDF files containing text, which the application processes by extracting content and applying the selected operation (encrypt or decrypt). The tool also supports handling binary padding and removal, ensuring that data integrity is maintained during processing. The encrypted or decrypted content is saved in a new PDF file, ensuring seamless usability.

This project emphasizes the use of object-oriented programming (OOP) principles, with clear modularization for components such as key generation, encryption, and decryption. Without relying on external DES libraries, the implementation showcases a deeper understanding of cryptographic principles.

Overall, this project serves as a secure, standalone solution for text encryption and decryption, aligning with modern demands for data confidentiality in digital documents.

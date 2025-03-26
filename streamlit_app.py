import streamlit as st

def vigenere_encrypt(plaintext: str, key: str, alphabet: str) -> str:
    if not alphabet:
        raise ValueError("Alphabet cannot be empty")
    if len(set(alphabet)) != len(alphabet):
        raise ValueError("Alphabet must contain unique characters")
    if not key:
        raise ValueError("Key cannot be empty")
    if not plaintext:
        raise ValueError("Plaintext cannot be empty")

    alphabet_set = set(alphabet)
    key = ''.join(c for c in key if c in alphabet_set)

    if not key:
        raise ValueError("Key contains no valid characters")

    cipher_text = []
    key_index = 0

    for char in plaintext:
        if char in alphabet_set:
            char_index = alphabet.index(char)
            key_char = key[key_index % len(key)]
            key_index += 1
            key_val = alphabet.index(key_char)
            new_index = (char_index + key_val) % len(alphabet)
            cipher_text.append(alphabet[new_index])
        else:
            cipher_text.append(char)

    return ''.join(cipher_text)

def caesar_encrypt_decrypt(text, shift_keys, ifdecrypt):
    result = []
    shift_keys_len = len(shift_keys)

    for i, char in enumerate(text):
        if 32 <= ord(char) <= 126:
            shift = shift_keys[i % shift_keys_len]
            effective_shift = -shift if ifdecrypt else shift
            shifted_char = chr((ord(char) - 32 + effective_shift) % 94 + 32)
            result.append(shifted_char)
        else:
            result.append(char)

    return ''.join(result)

def primitive_root(g, n):
    req_set = {num for num in range(1, n)}
    gen_set = {pow(g, power, n) for power in range(1, n)}
    return req_set == gen_set
def encrypt_decrypt(text, key, operation):
    if len(key) != 8:
        return "Error: Key must be exactly 8 characters"
    if operation == 'encrypt':
        return encrypt(text, key)
    elif operation == 'decrypt':
        return decrypt(text, key)
    else:
        return "Error: Invalid operation. Use 'encrypt' or 'decrypt'"

def find_primitive_roots(n):
    pri_roots = []
    for g in range(1, n):
        if primitive_root(g, n):
            pri_roots.append(g)
    return pri_roots
def encrypt(text, key):
    text = pad_message(text)
    result = []
    
    for i in range(0, len(text), 8):
        block = text[i:i+8]
        encrypted_block = xor_operation(block, key)
        result.extend(encrypted_block)
    
    return ' '.join(format(byte, '02X') for byte in result)

def print_mod_expo(n):
    pri_roots = find_primitive_roots(n)
    results = []
    for g in range(1, n):
        result_list = []
        value = 1
        for power in range(1, n):
            value = pow(g, power, n)
            result_list.append(f"{g}^{power} mod {n} = {value}")
            if value == 1 and power < n - 1:
                break
        result_str = ", ".join(result_list)
        if g in pri_roots:
            results.append(f"{result_str} ==> {g} is primitive root of {n}")
        else:
            results.append(f"{result_str}")
    return pri_roots, results
def decrypt(hex_text, key):
    try:
        hex_values = [int(h, 16) for h in hex_text.split()]
    except ValueError:
        return "Error: Invalid hex input for decryption"
        
    result = []
    for i in range(0, len(hex_values), 8):
        block = hex_values[i:i+8]
        decrypted_block = ''.join(chr(b ^ ord(k)) for b, k in zip(block, key))
        result.append(decrypted_block)
        
    return remove_padding(''.join(result))

def pad_message(message, block_size=8, padding_char='_'):
    padding_length = (block_size - len(message) % block_size) % block_size
    return message + (padding_char * padding_length)

def remove_padding(message, padding_char='_'):
    return message.rstrip(padding_char)

def xor_operation(block, key):
    return [ord(b) ^ ord(k) for b, k in zip(block, key)]

# Streamlit UI
st.title("Encryption & Primitive Root Tool")
st.title("Cipher Encryption Tool")

cipher_choice = st.sidebar.radio("Choose Method:", ["Vigenère Cipher", "Caesar Cipher", "Primitive Root Calculation"])
cipher_choice = st.sidebar.radio("Choose Encryption Method:", ["Vigenère Cipher", "Caesar Cipher", "Primitive Root", "XOR Encryption"])

if cipher_choice == "Vigenère Cipher":
    st.header("Vigenère Cipher Encryption")
    alphabet = st.text_input("Enter Alphabet:")
    alphabet = st.text_input("Enter Alphabet:", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    key = st.text_input("Enter Key:")
    plaintext = st.text_input("Enter Plaintext:")
    if st.button("Encrypt"):
    @@ -106,19 +121,11 @@
            result_text = caesar_encrypt_decrypt(text, shift_keys, ifdecrypt=(operation == "Decrypt"))
            st.write(f"### {operation}ed Message:", result_text)

elif cipher_choice == "Primitive Root Calculation":
    st.header("Primitive Root Calculation")
    n = st.number_input("Enter Prime Number:", min_value=2, step=1)
    g = st.number_input("Enter Possible Primitive Root:", min_value=1, step=1)
    if st.button("Check"):
        if n < 2 or any(n % i == 0 for i in range(2, int(n ** 0.5) + 1)):
            st.write(f"{n} is not a prime number!!")
        else:
            pri_roots, results = print_mod_expo(n)
            for res in results:
                st.write(res)
            is_g_primitive = g in pri_roots
            if is_g_primitive:
                st.write(f"{g} is a primitive root of {n}. List of Primitive Roots: {pri_roots}")
            else:
                st.write(f"{g} is NOT a primitive root of {n}. List of Primitive Roots: {pri_roots}")
elif cipher_choice == "XOR Encryption":
    st.header("XOR Encryption")
    text = st.text_input("Enter Text:")
    key = st.text_input("Enter 8-character Key:")
    operation = st.radio("Choose Operation:", ["Encrypt", "Decrypt"])
    if st.button("Process"):
        result = encrypt_decrypt(text, key, operation.lower())
        st.write(f"### {operation}ed Message:", result)

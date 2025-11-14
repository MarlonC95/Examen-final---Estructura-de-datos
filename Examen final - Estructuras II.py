import os
import heapq
import random
import struct
from collections import Counter, defaultdict
import binascii

class HuffmanCompression:
    class Node:
        def __init__(self, char, freq):
            self.char = char
            self.freq = freq
            self.left = None
            self.right = None
        
        def __lt__(self, other):
            return self.freq < other.freq
    
    def __init__(self):
        self.codes = {}
        self.reverse_mapping = {}
    
    def build_frequency_table(self, text):
        return Counter(text)
    
    def build_heap(self, freq):
        heap = []
        for char, frequency in freq.items():
            node = self.Node(char, frequency)
            heapq.heappush(heap, node)
        return heap
    
    def build_tree(self, heap):
        while len(heap) > 1:
            node1 = heapq.heappop(heap)
            node2 = heapq.heappop(heap)
            merged = self.Node(None, node1.freq + node2.freq)
            merged.left = node1
            merged.right = node2
            heapq.heappush(heap, merged)
        return heap[0]
    
    def build_codes(self, node, current_code=""):
        if node is None:
            return
        
        if node.char is not None:
            self.codes[node.char] = current_code
            self.reverse_mapping[current_code] = node.char
            return
        
        self.build_codes(node.left, current_code + "0")
        self.build_codes(node.right, current_code + "1")
    
    def compress(self, text):
        if not text:
            return "", {}
        
        freq = self.build_frequency_table(text)
        heap = self.build_heap(freq)
        root = self.build_tree(heap)
        
        self.codes = {}
        self.reverse_mapping = {}
        self.build_codes(root)
        
        encoded_text = ''.join(self.codes[char] for char in text)
        extra_padding = 8 - len(encoded_text) % 8
        encoded_text += '0' * extra_padding
        byte_array = bytearray()
        for i in range(0, len(encoded_text), 8):
            byte = encoded_text[i:i+8]
            byte_array.append(int(byte, 2))
        
        return bytes(byte_array), self.reverse_mapping, extra_padding
    
    def decompress(self, encoded_bytes, reverse_mapping, extra_padding):
        bit_string = ""
        for byte in encoded_bytes:
            bits = bin(byte)[2:].rjust(8, '0')
            bit_string += bits
        bit_string = bit_string[:-extra_padding] if extra_padding > 0 else bit_string
        current_code = ""
        decoded_text = ""
        
        for bit in bit_string:
            current_code += bit
            if current_code in reverse_mapping:
                decoded_text += reverse_mapping[current_code]
                current_code = ""
        
        return decoded_text

class RSAEncryption:
    
    def __init__(self, key_size=512): 
        self.key_size = key_size
        self.public_key = None
        self.private_key = None
    
    def gcd(self, a, b):
        while b != 0:
            a, b = b, a % b
        return a
    
    def mod_inverse(self, a, m):
        if self.gcd(a, m) != 1:
            return None
        u1, u2, u3 = 1, 0, a
        v1, v2, v3 = 0, 1, m
        
        while v3 != 0:
            q = u3 // v3
            v1, v2, v3, u1, u2, u3 = (
                u1 - q * v1,
                u2 - q * v2,
                u3 - q * v3,
                v1, v2, v3
            )
        return u1 % m
    
    def is_prime(self, n, k=5):
        if n < 2:
            return False
        small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
        for p in small_primes:
            if n % p == 0:
                return n == p
        if n < 1000:
            for i in range(2, int(n**0.5) + 1):
                if n % i == 0:
                    return False
            return True
        for _ in range(k):
            a = random.randint(2, n - 2)
            if pow(a, n - 1, n) != 1:
                return False
        return True
    
    def generate_prime_candidate(self):
        """Genera un candidato a número primo"""
        p = random.getrandbits(self.key_size // 2)
        p |= (1 << (self.key_size // 2 - 1)) | 1
        return p
    
    def generate_prime_number(self):
        p = 4
        while not self.is_prime(p):
            p = self.generate_prime_candidate()
        return p
    
    def generate_keys(self):
        print("Generando primer número primo...")
        p = self.generate_prime_number()
        print("Generando segundo número primo...")
        q = self.generate_prime_number()
        while p == q:
            q = self.generate_prime_number()
        
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        while self.gcd(e, phi) != 1:
            e = random.randint(2, phi - 1)
        print("Calculando inverso modular...")
        d = self.mod_inverse(e, phi)
        
        self.public_key = (e, n)
        self.private_key = (d, n)
        
        return self.public_key, self.private_key
    
    def sign(self, hash_value, private_key):
        d, n = private_key
        hash_int = int(hash_value, 16)
        if hash_int >= n:
            hash_int = hash_int % n
        
        signature = pow(hash_int, d, n)
        return signature
    
    def verify(self, signature, hash_value, public_key):
        e, n = public_key
        decrypted_hash_int = pow(signature, e, n)
        original_hash_int = int(hash_value, 16)
        return decrypted_hash_int == original_hash_int

class FNV1Hash:
    def __init__(self):
        self.FNV_prime_32 = 16777619
        self.FNV_offset_basis_32 = 2166136261
    
    def hash_32(self, text):
        hash_value = self.FNV_offset_basis_32
        for byte in text.encode('utf-8'):
            hash_value = (hash_value * self.FNV_prime_32) & 0xFFFFFFFF
            hash_value ^= byte
        return format(hash_value, '08x')

class MessageSystem:
    def __init__(self):
        self.message = ""
        self.hash_value = ""
        self.compressed_data = None
        self.huffman_mapping = None
        self.padding = 0
        self.signature = None
        self.rsa = RSAEncryption()
        self.huffman = HuffmanCompression()
        self.fnv = FNV1Hash()
        self.sent_data = {}
    
    def display_menu(self):
        print("\n" + "="*50)
        print("SISTEMA DE FIRMA Y VERIFICACIÓN DE MENSAJES")
        print("="*50)
        print("1. Ingresar mensaje")
        print("2. Calcular hash FNV-1")
        print("3. Comprimir mensaje (Huffman)")
        print("4. Generar claves RSA y firmar hash")
        print("5. Simular envío")
        print("6. Descomprimir y verificar firma")
        print("7. Mostrar resultados de autenticidad")
        print("8. Salir")
        print("-"*50)
    
    def input_message(self):
        self.message = input("Ingrese el mensaje de texto: ")
        print(f"Mensaje ingresado: {self.message}")
        print(f"Tamaño del mensaje: {len(self.message)} caracteres")
    
    def calculate_hash(self):
        if not self.message:
            print("Error: Primero ingrese un mensaje (opción 1)")
            return
        
        self.hash_value = self.fnv.hash_32(self.message)
        print(f"Hash FNV-1 calculado: {self.hash_value}")
    
    def compress_message(self):
        if not self.message:
            print("Error: Primero ingrese un mensaje (opción 1)")
            return
        
        original_size = len(self.message.encode('utf-8'))
        self.compressed_data, self.huffman_mapping, self.padding = self.huffman.compress(self.message)
        compressed_size = len(self.compressed_data)
        
        print(f"Tamaño antes de compresión: {original_size} bytes")
        print(f"Tamaño después de compresión: {compressed_size} bytes")
        if original_size > 0:
            compression_ratio = (1 - compressed_size / original_size) * 100
            print(f"Ratio de compresión: {compression_ratio:.2f}%")
        
        print("Mensaje comprimido exitosamente")
    
    def generate_keys_and_sign(self):
        if not self.hash_value:
            print("Error: Primero calcule el hash (opción 2)")
            return
        
        print("Generando claves RSA...")
        public_key, private_key = self.rsa.generate_keys()
        
        print("Claves generadas:")
        print(f"Clave pública (e, n): {public_key}")
        print(f"Clave privada (d, n): {private_key}")
        self.signature = self.rsa.sign(self.hash_value, private_key)
        print(f"Firma digital generada: {self.signature}")
    
    def simulate_send(self):
        if not self.compressed_data or not self.signature or not self.rsa.public_key:
            print("Error: Complete los pasos anteriores (3 y 4)")
            return
        
        self.sent_data = {
            'compressed_message': self.compressed_data,
            'signature': self.signature,
            'public_key': self.rsa.public_key,
            'huffman_mapping': self.huffman_mapping,
            'padding': self.padding
        }
        
        print("Envío simulado exitosamente:")
        print("- Mensaje comprimido enviado")
        print("- Firma digital enviada")
        print("- Clave pública enviada")
        print("(Clave privada NO enviada)")
    
    def decompress_and_verify(self):
        if not self.sent_data:
            print("Error: Primero simule el envío (opción 5)")
            return
        
        try:
            compressed_msg = self.sent_data['compressed_message']
            mapping = self.sent_data['huffman_mapping']
            padding = self.sent_data['padding']
            
            print("Descomprimiendo mensaje...")
            received_message = self.huffman.decompress(compressed_msg, mapping, padding)
            print("Calculando hash del mensaje recibido...")
            received_hash = self.fnv.hash_32(received_message)
            signature = self.sent_data['signature']
            public_key = self.sent_data['public_key']
            
            print("Verificando firma digital...")
            is_valid = self.rsa.verify(signature, received_hash, public_key)
            
            print("Proceso de verificación completado:")
            print(f"Mensaje recibido: {received_message}")
            print(f"Hash calculado del mensaje recibido: {received_hash}")
            print(f"Firma verificada: {'VÁLIDA' if is_valid else 'INVÁLIDA'}")
            
            self.verification_result = {
                'is_valid': is_valid,
                'received_message': received_message,
                'received_hash': received_hash
            }
            
        except Exception as e:
            print(f"Error durante la verificación: {e}")
            import traceback
            traceback.print_exc()
    
    def show_authentication_result(self):
        if not hasattr(self, 'verification_result'):
            print("Error: Primero realice la verificación (opción 6)")
            return
        
        result = self.verification_result
        if result['is_valid']:
            print("\n" + "="*50)
            print("MENSAJE AUTÉNTICO Y NO MODIFICADO")
            print("="*50)
            print(f"Mensaje original: {result['received_message']}")
            print(f"Hash verificado: {result['received_hash']}")
        else:
            print("\n" + "="*50)
            print("MENSAJE ALTERADO O FIRMA NO VÁLIDA")
            print("="*50)

def main():
    system = MessageSystem()
    
    while True:
        os.system('cls')
        system.display_menu()
        choice = input("Seleccione una opción (1-8): ")
        if choice == '1':
            os.system('cls')
            system.input_message()
        elif choice == '2':
            os.system('cls')
            system.calculate_hash()
        elif choice == '3':
            os.system('cls')
            system.compress_message()
        elif choice == '4':
            os.system('cls')
            system.generate_keys_and_sign()
        elif choice == '5':
            os.system('cls')
            system.simulate_send()
        elif choice == '6':
            os.system('cls')
            system.decompress_and_verify()
        elif choice == '7':
            os.system('cls')
            system.show_authentication_result()
        elif choice == '8':
            os.system('cls')
            print("¡Hasta luego!")
            break
        else:
            os.system('cls')
            print("Opción inválida. Por favor seleccione 1-8.")
        
        input("\nPresione Enter para continuar...")

if __name__ == "__main__":
    main()
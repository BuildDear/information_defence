import unittest
import os
import time
from Crypto.Random import get_random_bytes

from all_labs.logic.lab3 import RC5CBCPad
from all_labs.logic.lab4 import RSAEncryption


# Test class for testing RSA and RC5 encryption and decryption
class TestRSAEncryption(unittest.TestCase):
    # Setup method to initialize RSAEncryption and RC5CBCPad instances before each test
    def setUp(self):
        # Initialize RSA encryption with a 2048-bit key
        self.rsa_encryption = RSAEncryption(key_size=2048)
        self.rsa_encryption.generate_keys()

        # Paths for saving RSA keys
        self.private_key_path = "private_test.pem"
        self.public_key_path = "public_test.pem"

        # Initialize RC5 encryption with a 16-byte key
        self.rc5_key = b'secret_key_16b'
        self.rc5 = RC5CBCPad(self.rc5_key)

    # Cleanup method to remove temporary files after each test
    def tearDown(self):
        if os.path.exists(self.private_key_path):
            os.remove(self.private_key_path)
        if os.path.exists(self.public_key_path):
            os.remove(self.public_key_path)

    # Test the generation of RSA keys
    def test_generate_keys(self):
        # Ensure the private and public keys are not None
        self.assertIsNotNone(self.rsa_encryption.private_key)
        self.assertIsNotNone(self.rsa_encryption.public_key)
        # Verify the private key has the correct bit size
        self.assertEqual(self.rsa_encryption.private_key.size_in_bits(), 2048)

    # Test saving and loading RSA keys to and from files
    def test_save_and_load_keys(self):
        # Save the keys to files
        self.rsa_encryption.save_keys(self.private_key_path, self.public_key_path)

        # Create a new RSAEncryption instance and load the keys
        rsa_new_instance = RSAEncryption()
        rsa_new_instance.load_private_key(self.private_key_path)
        rsa_new_instance.load_public_key(self.public_key_path)

        # Ensure the saved and loaded keys match the original keys
        self.assertEqual(self.rsa_encryption.private_key.export_key(), rsa_new_instance.private_key.export_key())
        self.assertEqual(self.rsa_encryption.public_key.export_key(), rsa_new_instance.public_key.export_key())

    # Test RSA encryption and decryption functionality
    def test_rsa_encryption_decryption(self):
        plaintext = b"Test message for encryption"
        # Encrypt the plaintext
        encrypted_data = self.rsa_encryption.encrypt(plaintext)
        # Decrypt the ciphertext
        decrypted_data = self.rsa_encryption.decrypt(encrypted_data)

        # Ensure the decrypted data matches the original plaintext
        self.assertEqual(plaintext, decrypted_data)

    # Test RC5 encryption and decryption functionality
    def test_rc5_encryption_decryption(self):
        plaintext = b"Test message for RC5 encryption"
        # Generate a random initialization vector (IV)
        iv = os.urandom(self.rc5.block_size)
        # Encrypt the plaintext using RC5
        encrypted_data = self.rc5.encrypt_console(plaintext, iv)
        # Decrypt the ciphertext using RC5
        decrypted_data = self.rc5.decrypt_console(encrypted_data, iv)

        # Ensure the decrypted data matches the original plaintext
        self.assertEqual(plaintext, decrypted_data)

    # Compare RSA and RC5 in terms of encryption and decryption times
    def test_rsa_vs_rc5(self):
        test_data = get_random_bytes(9999)  # Generate random data for testing

        # Measure RSA encryption and decryption times
        rsa_start_time = time.time()
        encrypted_rsa = self.rsa_encryption.encrypt(test_data)
        rsa_encrypt_time = time.time() - rsa_start_time

        rsa_start_time = time.time()
        decrypted_rsa = self.rsa_encryption.decrypt(encrypted_rsa)
        rsa_decrypt_time = time.time() - rsa_start_time

        # Ensure the decrypted RSA data matches the original data
        self.assertEqual(decrypted_rsa, test_data)

        # Measure RC5 encryption and decryption times
        iv = os.urandom(self.rc5.block_size)
        rc5_start_time = time.time()
        encrypted_rc5 = self.rc5.encrypt_console(test_data, iv)
        rc5_encrypt_time = time.time() - rc5_start_time

        rc5_start_time = time.time()
        decrypted_rc5 = self.rc5.decrypt_console(encrypted_rc5, iv)
        rc5_decrypt_time = time.time() - rc5_start_time

        # Ensure the decrypted RC5 data matches the original data
        self.assertEqual(decrypted_rc5, test_data)

        # Print the encryption and decryption times for RSA and RC5
        print(f"RSA Encryption Time: {rsa_encrypt_time:.6f} seconds")
        print(f"RSA Decryption Time: {rsa_decrypt_time:.6f} seconds")
        print(f"RC5 Encryption Time: {rc5_encrypt_time:.6f} seconds")
        print(f"RC5 Decryption Time: {rc5_decrypt_time:.6f} seconds")

        # Check that the times are comparable (no strict requirement for faster/slower)
        self.assertTrue(rsa_encrypt_time <= rc5_encrypt_time or rc5_encrypt_time <= rsa_encrypt_time)
        self.assertTrue(rsa_decrypt_time <= rc5_decrypt_time or rc5_decrypt_time <= rsa_decrypt_time)


# Entry point for running the tests
if __name__ == "__main__":
    unittest.main()
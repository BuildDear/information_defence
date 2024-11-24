import unittest

from all_labs.logic.lab3 import RC5CBCPad

# Test class for testing the RC5CBCPad encryption and decryption functionality
class TestRC5CBCPad(unittest.TestCase):
    # Setup method to initialize an RC5CBCPad instance with a secret key
    def setUp(self):
        self.rc5 = RC5CBCPad(key=b"secret_key")

    # Test the _pad_key method to ensure it correctly pads keys to the specified length
    def test_pad_key(self):
        padded_key = self.rc5._pad_key(b"short_key", 16)  # Pad a key to 16 bytes
        self.assertEqual(len(padded_key), 16)  # Check that the padded key is 16 bytes long

    # Test the _xor_bytes method to ensure it performs XOR operation correctly on two byte strings
    def test_xor_bytes(self):
        result = self.rc5._xor_bytes(b"\x01\x02", b"\x03\x04")  # XOR two byte strings
        self.assertEqual(result, b"\x02\x06")  # Verify the XOR result is correct

    # Test the _pad_data method to ensure it pads data to a multiple of the block size
    def test_pad_data(self):
        padded_data = self.rc5._pad_data(b"test")  # Pad the string "test"
        self.assertEqual(len(padded_data) % self.rc5.block_size, 0)  # Check that the length is a multiple of block size

    # Test the _unpad_data method to ensure it removes padding correctly
    def test_unpad_data(self):
        padded_data = self.rc5._pad_data(b"test")  # Pad the string "test"
        unpadded_data = self.rc5._unpad_data(padded_data)  # Remove the padding
        self.assertEqual(unpadded_data, b"test")  # Verify the unpadded data matches the original data

    # Test the encryption and decryption process to ensure they work together correctly
    def test_encrypt_decrypt(self):
        data = b"hello world!!"  # Input data for encryption
        padded_data = self.rc5._pad_data(data)  # Pad the input data
        # Encrypt each block of the padded data
        encrypted_blocks = [self.rc5._rc5_encrypt_block(block) for block in self.rc5._split_blocks(padded_data)]
        # Decrypt each encrypted block
        decrypted_blocks = [self.rc5._rc5_decrypt_block(block) for block in encrypted_blocks]
        # Remove the padding from the decrypted data
        decrypted_data = self.rc5._unpad_data(b"".join(decrypted_blocks))
        # Verify that the decrypted data matches the original input
        self.assertEqual(decrypted_data, data)

# Entry point for running the tests
if __name__ == "__main__":
    unittest.main()
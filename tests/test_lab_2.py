import unittest

from all_labs.logic.lab2 import MD5, md5_string, md5_file, verify_file

# Test class for testing the MD5 hashing functionality
class TestMD5(unittest.TestCase):

    # Test the MD5 class to ensure it correctly computes hash values
    def test_md5_hashing(self):
        md5 = MD5()  # Create an instance of the MD5 class
        md5.update(b"test")  # Update the MD5 object with test data
        self.assertEqual(len(md5.hexdigest()), 32)  # Verify that the hash has the correct length (32 hex characters)

    # Test the md5_string function to ensure it computes the hash for strings correctly
    def test_md5_string(self):
        hash_result = md5_string("test")  # Compute MD5 hash of the string "test"
        self.assertEqual(len(hash_result), 32)  # Check that the hash length is 32
        self.assertIsInstance(hash_result, str)  # Ensure the result is a string


# Entry point for running the tests
if __name__ == "__main__":
    unittest.main()

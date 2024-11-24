import unittest
import tempfile
import os

from lab5.business.lab5 import generate_keys, verify_signature, sign_data


class TestDigitalSignature(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Створюємо тимчасові файли для збереження ключів
        cls.private_key_path = tempfile.NamedTemporaryFile(delete=False).name
        cls.public_key_path = tempfile.NamedTemporaryFile(delete=False).name
        generate_keys(cls.private_key_path, cls.public_key_path)

    @classmethod
    def tearDownClass(cls):
        # Видаляємо тимчасові файли після завершення тестів
        os.remove(cls.private_key_path)
        os.remove(cls.public_key_path)

    def test_generate_keys(self):
        """Перевірка, чи створені файли з приватним і публічним ключами."""
        self.assertTrue(os.path.exists(self.private_key_path), "Private key file was not created.")
        self.assertTrue(os.path.exists(self.public_key_path), "Public key file was not created.")

    def test_sign_and_verify_correct_signature(self):
        """Тестуємо підпис даних та перевіряємо валідність підпису з правильним ключем."""
        data = b"Test message for signing"
        signature = sign_data(data, self.private_key_path)

        # Перевіряємо, що підпис правильний
        self.assertTrue(verify_signature(data, signature, self.public_key_path), "The signature should be valid.")

    def test_verify_incorrect_signature(self):
        """Перевіряємо, що невірний підпис не пройде перевірку."""
        data = b"Another message"
        invalid_signature = "abcd1234"  # Некоректний підпис

        # Перевіряємо, що перевірка невірного підпису повертає False
        self.assertFalse(verify_signature(data, invalid_signature, self.public_key_path),
                         "The signature should be invalid.")

    def test_sign_and_verify_with_modified_data(self):
        """Перевірка, що підпис недійсний, якщо дані були змінені."""
        data = b"Original message"
        modified_data = b"Modified message"
        signature = sign_data(data, self.private_key_path)

        # Перевіряємо, що підпис для оригінальних даних не пройде для змінених даних
        self.assertFalse(verify_signature(modified_data, signature, self.public_key_path),
                         "The signature should be invalid for modified data.")


if __name__ == "__main__":
    unittest.main()

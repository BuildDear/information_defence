import unittest

from all_labs.logic.lab1 import LemerGenerator, gcd, estimate_pi

# Test class for testing the functionality of LemerGenerator
class TestLemerGenerator(unittest.TestCase):
    def setUp(self):
        # Initialize an instance of LemerGenerator with specific parameters for testing
        self.gen = LemerGenerator(seed=11, a=48271, c=0, m=2**31)

    # Test the next() method to ensure it generates integers and appends them to the list
    def test_next_generation(self):
        number = self.gen.next()  # Generate the next number
        self.assertIsInstance(number, int)  # Check that the generated number is an integer
        self.assertEqual(len(self.gen.generated_numbers), 1)  # Check that the list has one element

    # Test the get_bytes() method to ensure it returns the correct amount of bytes
    def test_get_bytes(self):
        bytes_data = self.gen.get_bytes(16)  # Request 16 bytes
        self.assertEqual(len(bytes_data), 16)  # Verify that the returned data has 16 bytes

    # Test the save_to_file() method to ensure it correctly saves generated numbers to a file
    def test_save_to_file(self):
        self.gen.next()  # Generate one number
        self.gen.save_to_file("files/file_test_output.txt")  # Save to file
        with open("files/file_test_output.txt", "r") as f:
            lines = f.readlines()  # Read the contents of the file
        self.assertEqual(len(lines), 1)  # Verify that one line is written to the file

    # Test the find_period() method to check the detected period of the generator
    def test_find_period(self):
        for _ in range(100):
            self.gen.next()  # Generate 100 numbers
        period = self.gen.find_period()  # Find the period
        self.assertGreaterEqual(period, 1)  # Verify that the period is at least 1

# Test class for testing general mathematical functions
class TestMathFunctions(unittest.TestCase):
    # Test the gcd() function to ensure it calculates the greatest common divisor correctly
    def test_gcd(self):
        self.assertEqual(gcd(54, 24), 6)  # GCD of 54 and 24 is 6
        self.assertEqual(gcd(101, 10), 1)  # GCD of 101 and 10 is 1 (coprime)

    # Test the estimate_pi() function to ensure it returns a floating-point number
    def test_estimate_pi(self):
        estimate = estimate_pi(1000, lambda: 42)  # Estimate pi using a constant RNG (for determinism)
        self.assertIsInstance(estimate, float)  # Verify the result is a float


# Entry point for running the tests
if __name__ == "__main__":
    unittest.main()
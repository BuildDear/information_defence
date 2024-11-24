import math


class LemerGenerator:
    def __init__(self, seed=1, a=48271, c=0, m=2 ** 31):
        self.a = a
        self.c = c
        self.m = m
        self.state = seed
        self.generated_numbers = []

    def next(self):
        """Generates the next number in the sequence."""
        self.state = (self.a * self.state + self.c) % self.m
        self.generated_numbers.append(self.state)
        return self.state

    def get_bytes(self, num_bytes):
        """Generates `num_bytes` worth of random data."""
        result = b''
        while len(result) < num_bytes:
            number = self.next()
            result += number.to_bytes(4, byteorder='big')
        return result[:num_bytes]

    def save_to_file(self, filename):
        """Saves generated numbers to a file."""
        try:
            with open(filename, 'w') as f:
                for num in self.generated_numbers:
                    f.write(f"{num}\n")
        except IOError as e:
            print(f"Error saving file: {e}")

    def find_period(self):
        sequence = self.generated_numbers
        length = len(sequence)
        for period in range(1, length // 2 + 1):
            if sequence[:period] == sequence[period:2 * period]:
                return period
        return length


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def estimate_pi(num_pairs, rng_function):
    coprime_count = 0
    for _ in range(num_pairs):
        num1 = rng_function()
        num2 = rng_function()
        if gcd(num1, num2) == 1:
            coprime_count += 1

    probability = coprime_count / num_pairs
    pi_estimate = math.sqrt(6 / probability) if probability > 0 else float('inf')
    return pi_estimate


def generate_lemer_numbers(num_pairs, seed=11, a=12 ** 3, c=987, m=2 ** 25 - 1):
    lemer_gen = LemerGenerator(seed=seed, a=a, c=c, m=m)

    # Generate numbers and store them in generated_numbers list
    for _ in range(num_pairs):
        lemer_gen.next()

    pi_est_lemer = estimate_pi(num_pairs, lemer_gen.next)
    period = lemer_gen.find_period()

    # Generate first 16 bytes for display
    bytes_data = lemer_gen.get_bytes(16).hex()

    return {
        'pi_lemer': pi_est_lemer,
        'period': period,
        'generated_numbers': lemer_gen.generated_numbers[:10],
        'first_16_bytes': bytes_data
    }

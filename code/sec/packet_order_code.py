import itertools
import math


class PermutationConfig:
    def __init__(self, K=4, BPS=4):
        self.K = K
        self.BPS = BPS
        self.L = 2**self.BPS
        assert self.L <= math.factorial(self.K), (
            "Number of symbols exceeds available codewords"
        )


def gen_permutations(conf: PermutationConfig):
    # All possible permutations (K!)
    perms = list(itertools.permutations(range(conf.K), conf.K))

    # Calculate the step size for even spacing
    step = len(perms) // conf.L

    # Select L permutations evenly spaced
    selected_perms = [perms[i * step] for i in range(conf.L)]

    return selected_perms


def gen_bit_string_to_permutation_map(conf: PermutationConfig):
    """
    Creates a mapping from bit strings (of length BPS) to permutations.

    Returns:
        dict: A dictionary mapping each bit string to its corresponding permutation.
    """
    permutations = gen_permutations(conf)
    bit_string_to_perm = {}

    # Map each bit string to its corresponding permutation
    for symbol in range(conf.L):
        # Convert the symbol to a binary string of length BPS
        bit_string = format(symbol, f"0{conf.BPS}b")
        bit_string_to_perm[bit_string] = tuple(permutations[symbol])

    return bit_string_to_perm


# Not all permutations may exist in this mapping
# TODO: Maybe implement error correction by mapping missing permutations to the closest one
def gen_permutation_to_bit_string_map(conf: PermutationConfig):
    symbol_to_perm_map = gen_bit_string_to_permutation_map(conf)
    perm_to_symbol_map = {v: k for k, v in symbol_to_perm_map.items()}
    return perm_to_symbol_map


def get_bit_string(data_bytes, BPS):
    """
    Converts bytes to a string of bits, ensuring the length is a multiple of BPS.

    Args:
        data_bytes (bytes): The input bytes to convert

    Returns:
        str: A string of bits ('0's and '1's) with length divisible by BPS
    """
    # Convert bytes to a string of bits
    bit_string = "".join(format(byte, "08b") for byte in data_bytes)

    # Calculate padding needed to make length divisible by BPS
    remainder = len(bit_string) % BPS
    padding_length = 0 if remainder == 0 else BPS - remainder

    # Pad the bit string to make its length divisible by BPS
    padded_bit_string = bit_string + "0" * padding_length

    return padded_bit_string


def get_byte_from_bit_string(bit_string):
    """
    Converts a string of bits to bytes.

    Args:
        bit_string (str): The input string of bits ('0's and '1's)

    Returns:
        bytes: The converted bytes
    """
    # Convert the bit string to bytes
    byte_array = bytearray(
        int(bit_string[i : i + 8], 2) for i in range(0, len(bit_string), 8)
    )

    return bytes(byte_array)

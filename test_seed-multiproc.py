import pstats
from mnemonic import Mnemonic
from bip32 import BIP32
from bech32 import bech32_encode, convertbits
import hashlib
import os
from dotenv import load_dotenv
from multiprocessing import Pool
from concurrent.futures import ThreadPoolExecutor
import cProfile
import sys

# Load the .env file
load_dotenv()

seed_phrase = os.getenv('SEED_PHRASE')
mnemo = Mnemonic("english")
counter = 0

def get_words_starting_with(prefix):
    words = []
    with open('data/bip39-english.txt', 'r') as f:
        for line in f:
            word = line.strip()
            if word.startswith(prefix):
                words.append(word)
    return words

def generate_new_seed(seed_words, positions, candidate_word):
    new_seed_words = seed_words.split()
    for pos, word in zip(positions, candidate_word.split()):
        new_seed_words[pos - 1] = word
    return " ".join(new_seed_words)

def is_valid_bitcoin_wallet(seed):
    return mnemo.check(seed)


def check_combination(pos1_word, pos2_word, pos3_word):
    new_seed = generate_new_seed(seed_phrase, [pos1, pos2, pos3], f"{pos1_word} {pos2_word} {pos3_word}")
    
    global counter
    counter += 1
    if counter % 50000 == 0:
        print(f"Checked {counter} combinations")

    if is_valid_bitcoin_wallet(new_seed):
        seed = mnemo.to_seed(new_seed)
        bip32 = BIP32.from_seed(seed)
        addresses = []
        for account in range(total_accounts):
            for i in range(total_wallets):
                derivation_path = f"m/84'/0'/{account}'/0/{i}"
                public_key = bip32.get_pubkey_from_path(derivation_path)
                pubkey_hash = hashlib.new('ripemd160', hashlib.sha256(public_key).digest()).digest()
                witness_program = bytes([0x00]) + len(pubkey_hash).to_bytes(1, 'big') + pubkey_hash
                witness_version, witness_program = witness_program[0], witness_program[2:]
                converted_bits = convertbits(witness_program, 8, 5)
                address = bech32_encode('bc', [witness_version] + converted_bits)
                addresses.append(f"{derivation_path} {address}")
        
        return (new_seed, addresses)
    else:
        return None

output_file = "./potential_seeds.txt"

positions_to_fix = { 
    1: {5: get_words_starting_with("an")},
    2: {12: get_words_starting_with("")},
    3: {14: get_words_starting_with("")}
}

total_iterations = 1
for values in positions_to_fix.values():
    for words in values.values():
        total_iterations *= len(words)
print("Total Iterations:", total_iterations)

# print(f"Testing seed: {is_valid_bitcoin_wallet(seed_phrase)}")

total_processes = 20
total_wallets = 20
total_accounts = 2

print (f"Total wallets: {total_wallets * total_iterations}")
print (f"Starting with {total_processes} processes")
print (f"Total interactions per process: {total_iterations / total_processes}")

for pos1, words1 in positions_to_fix[1].items():
    for pos2, words2 in positions_to_fix[2].items():
        for pos3, words3 in positions_to_fix[3].items():
            continue

def main():
    with Pool(processes=total_processes) as pool:
        results = pool.starmap(check_combination, 
                               [(pos1_word, pos2_word, pos3_word) 
                                for pos1_word in positions_to_fix[1][pos1] 
                                for pos2_word in positions_to_fix[2][pos2] 
                                for pos3_word in positions_to_fix[3][pos3]])

        with open(output_file, "w") as f:
            with open('derived_addresses.txt', 'w') as derived:
                for result in results:
                    if result is not None:
                        new_seed, addresses = result
                        f.write(f"{new_seed}\n")
                        derived.write(f"Seed: {new_seed}\n")
                        for idx, address in enumerate(addresses):
                            derived.write(f"Address {idx + 1}: {address}\n")

if __name__ == '__main__':
    profiler = cProfile.Profile()
    profiler.enable()
    main()
    profiler.disable()
    with open('data/profiling.txt', 'w') as profiling:
        # Save stdout to a variable
        sys.stdout = profiling
    
        # Print the profiling statistics to the file
        stats = pstats.Stats(profiler, stream=sys.stdout)
        stats.sort_stats('time')
        stats.print_stats()

    # Restore stdout to the original value
    sys.stdout = sys.__stdout__

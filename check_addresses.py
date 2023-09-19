with open('data/addresses.txt', 'r') as f:
    addresses_to_search = set(line.strip() for line in f)

with open('derived_addresses.txt', 'r') as f:
    addresses_found = [line.strip() for line in f if any(address in line for address in addresses_to_search)]

with open('result.txt', 'w') as f:
    for address in addresses_found:
        print(f'Found: {address}')
        f.write(f"{address}\n")

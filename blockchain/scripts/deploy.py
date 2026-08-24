import json
import os
from web3 import Web3
from solcx import compile_standard, install_solc

# Install Solidity compiler (do once – comment out after first run)
install_solc('0.8.0')

# Connect to Ganache (make sure it's running on port 7545)
w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:7545'))
if not w3.is_connected():
    raise Exception("Ganache not running! Start it on port 7545.")

w3.eth.default_account = w3.eth.accounts[0]

# Read contract source
contract_path = os.path.join(os.path.dirname(__file__), '..', 'contracts', 'ThreatIntelligence.sol')
with open(contract_path, 'r') as f:
    contract_source = f.read()

# Compile
compiled = compile_standard({
    "language": "Solidity",
    "sources": {"ThreatIntelligence.sol": {"content": contract_source}},
    "settings": {"outputSelection": {"*": {"*": ["abi", "metadata", "evm.bytecode"]}}}
}, solc_version="0.8.0")

# Extract data
abi = compiled['contracts']['ThreatIntelligence.sol']['ThreatIntelligence']['abi']
bytecode = compiled['contracts']['ThreatIntelligence.sol']['ThreatIntelligence']['evm']['bytecode']['object']

# Deploy
contract = w3.eth.contract(abi=abi, bytecode=bytecode)
tx_hash = contract.constructor().transact()
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

contract_address = tx_receipt.contractAddress
print(f"✅ Contract deployed at: {contract_address}")

# Save address and ABI to build folder
build_dir = os.path.join(os.path.dirname(__file__), '..', 'build')
os.makedirs(build_dir, exist_ok=True)

with open(os.path.join(build_dir, 'contract_address.txt'), 'w') as f:
    f.write(contract_address)

with open(os.path.join(build_dir, 'abi.json'), 'w') as f:
    json.dump(abi, f)

print("✅ Address and ABI saved in 'blockchain/build/'")
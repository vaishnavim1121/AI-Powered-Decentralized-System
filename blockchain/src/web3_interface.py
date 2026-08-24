import json
import os
from web3 import Web3

class BlockchainInterface:
    def __init__(self):
        self.w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:7545'))
        if not self.w3.is_connected():
            raise Exception("Ganache not running on port 7545!")
        self.w3.eth.default_account = self.w3.eth.accounts[0]
        
        # Load address and ABI from build folder
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(base_dir, 'build', 'contract_address.txt'), 'r') as f:
            self.address = f.read().strip()
        with open(os.path.join(base_dir, 'build', 'abi.json'), 'r') as f:
            self.abi = json.load(f)
        self.contract = self.w3.eth.contract(address=self.address, abi=self.abi)
    
    def store_threat(self, threat_hash, severity=5):
        tx = self.contract.functions.submitThreat(threat_hash, severity).transact()
        receipt = self.w3.eth.wait_for_transaction_receipt(tx)
        return receipt['transactionHash'].hex()
    
    def get_threat(self, idx):
        return self.contract.functions.getThreat(idx).call()
    
    def get_count(self):
        return self.contract.functions.getCount().call()
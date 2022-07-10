# cd mockchain-python
# run python3 mockchain.py


import base64
import collections
import datetime
import hashlib
import ecdsa
import binascii


class Node:
    def __init__(self, name):
        self.name = name
        self._wallet = self.Wallet()
        self._blockchain = self.Blockchain()
        self._transaction_pool = self.TransactionPool()

    @property
    def wallet_id(self):
        return self._wallet.identity
    
    @property
    def get_block_count(self):
        return str(self._blockchain.block_count)
        
    @property
    def get_mempool_count(self):
        return str(self._transaction_pool.get_transaction_count)
        
    def sign_transaction(self, transaction):
        self._wallet.sign_transaction(transaction)
        
    def add_transaction_to_mempool(self, transaction):
        self._transaction_pool.append_transaction(transaction)
        
    def generate_block(self, block, difficulty):
        return self.Mining.generate_block(self._transaction_pool, block, difficulty)
        
    def append_block(self, block):
        self._blockchain.append_block(block)
        
    def validate_entire_blockchain(self, validate_signatures = True):
        self._blockchain.validate_entire_blockchain(validate_signatures)
        
    def print_blockchain_data(self, print_transaction_data = True):
        self._blockchain.print_blockchain_data(print_transaction_data)
        
    class Wallet:
        def __init__(self):
            ###
            # TODO:
            # 1. Generate new private key with ecdsa and SECP256k1
            # 2. Generate corresponding private key
            # 3. Hash the pubkey with sha256 ripemd160 to get a 20 byte PKH
            ###
            self._private_key = #TODO
            self._public_key = #TODO
            self.pub_key_hash = #TODO

        @property
        def identity(self):
            return self.pub_key_hash

        def sign_transaction(self, transaction):
            if transaction.sender != self.identity:
                raise Exception('The sender must be the one signing the transaction')
            # Create our text to sign
            message = transaction.unsigned_to_string.encode('utf-8')
            
            # TODO: Create a hash digest of the text to sign
            digest = #TODO
            # TODO: Sign the digest
            signature = #TODO
            # Get signature as b64 encoded string
            signature_b64_encoded = base64.b64encode(signature).decode('UTF-8')
            transaction.signature = signature_b64_encoded
            transaction.pub_key = self._public_key


    class Blockchain:
        def __init__(self):
            self._blocks = []
            self._utils = Utils()
        
        @property
        def block_count(self):
            return len(self._blocks)
            
        def append_block(self, block):
            self._blocks.append(block)

        def validate_entire_blockchain(self):
            previous_block_hash = ''
            block_hash = ''
            info = 'VALIDATING BLOCKCHAIN '
            log('\n' + str('=' * len(info)))
            log(info)
            log('=' * len(info))
                        
            for block in self._blocks:
                log('Verifying block ' + str(block.height))
                # Genesis block check
                if block.height == 1 :
                    previous_block_hash = Utils.sha256('Chancellor on brink of second bailout for banks')
                assert(block.previous_block_hash == previous_block_hash)
                previous_block_hash = block.derive_block_hash
                assert Utils.verify_pow(block, block.difficulty)
                log('Verified block hash (using nonce ' + str(block.nonce) + ')')
                for transaction in block.get_transactions:
                    assert Utils.verify_signature(transaction.signature, transaction.pub_key, transaction.unsigned_to_string)
                log('Verified transactions (' + str(len(block.get_transactions)) + ')')
                log('')
                    
        def print_blockchain_data (self, print_transaction_data = True):
            info = 'BLOCKCHAIN DATA'
            print('=' * len(info))
            print('' + info)
            print('=' * len(info))
            print('CHAIN LENGTH : ' + str(self.block_count))
            
            for block in self._blocks:
                info = 'BLOCK ' + str(block.height)
                print('\n' + info)
                print('=' * len(info))
                print('Block hash   : ' + str(block.get_block_hash))
                print('Prev block   : ' + str(block.get_previous_block_hash))
                print('Difficulty   : ' + str(block.difficulty))
                print('Nonce        : ' + str(block.nonce))
                print('Transactions : ' + str(len(block.get_transactions)))
                if print_transaction_data:
                    i = 1
                    for transaction in block.get_transactions:
                        tx_info = info + ' - TRANSACTION ' + str(i)
                        print('\n' + tx_info)
                        print('-' * len(tx_info))
                        transaction.print_transaction_data()
                        i += 1


    class Mining:
        @staticmethod
        def generate_block(mempool_transactions, previous_block, difficulty):
            block = Block()

            ### TODO: Implement block generation logic
            # 1. Add mempool TXs to your block (BONUS: If implementing UTXO and block reward logic, sort by fees and pay the fee to your miner node)
            # 2. Get previous block hash
            # 3. Mine new block
            ### 

            log('\nFound block ' + str(block.height) + ' using nonce ' + str(block.nonce))
            log('  Block ' + str(block.height) + ' hash: ' + block.id + '\n')
            # Remove mined transactions from the mempool
            if debug_log:
                block.print_transaction_ids()
            for transaction in block.get_transactions:
                # TODO: Update mempool
            return block

        @staticmethod
        def mine(block, difficulty=1, height=0):
            utils = Utils()
            nonce = None
            assert difficulty >= 1
            prefix = '0' * difficulty #TODO BONUS Implement difficultu as hexadecimal base/exponent calculation
            i = 0
            while not nonce:
                #TODO: Implement Proof of Work mining logic
                i += 1


    class TransactionPool:
        def __init__(self):
            self._transactions = []
        
        def append_transaction(self, transaction):
            if Utils.verify_signature(transaction.signature, transaction.pub_key, transaction.unsigned_to_string):
                self._transactions.append(transaction)
            else:
                raise Exception('Cannot add transaction to mempool - Invalid signature')
        
        @property
        def get_transactions(self):
            return self._transactions
            
        @property
        def get_transaction_count(self):
            return len(self._transactions)
            
        def remove_transaction(self, transaction):
            return self._transactions.remove(transaction)


class Block:
    def __init__(self):
        self._transactions = []
        self.previous_block_hash = None
        self.nonce = None
        self.height = 0
        self.difficulty = 0 #TODO BONUS: Implement difficulty as the real hexadecimal base/exponent formula
        self._block_hash = None

    @property
    def get_transactions(self):
        return self._transactions

    @property
    def get_previous_block_hash(self):
        return self.previous_block_hash
    
    @property
    def get_block_hash(self):
        if not self._block_hash:
            self.derive_block_hash
        return self._block_hash

    # Used to force recalculation of the block hash using block_data and nonce
    @property
    def derive_block_hash(self):
        if not self.nonce:
            raise Exception('You must set a valid nonce before trying to derive the block_hash')
        self._block_hash = #TODO Derive blockhash from all relevant block data, use the get_block_data_as_string function
        return self._block_hash

    def append_transaction(self, transaction):
        if Utils.verify_signature(transaction.signature, transaction.pub_key, transaction.unsigned_to_string):
            self._transactions.append(transaction)
        else:
            raise Exception('Cannot add transaction, invalid signature')

    @property
    def get_txs_string(self):
        txs_string = ''
        for transaction in self._transactions:
            txs_string += transaction.unsigned_to_string
        return txs_string
            
    @property
    def tx_count(self):
        return len(self._transactions)
    
    @property
    def get_block_data_as_string(self):
        block_string = #TODO concatenate all relevant blockdata for hashing
        return block_string

    def print_transaction_ids(self):
        print('  Transactions in block ' + str(self.height) + ':')
        for transaction in self._transactions:
            print('    ' + transaction.tx_id)


class Transaction:
    def __init__(self, sender, recipient, value):
        self._value = value
        self._time = datetime.datetime.now()
        self.sender = sender
        self.recipient = recipient
        self.signature = ''
        self.pub_key = ''

    @property
    def tx_id(self):
        return Utils.sha256(self.unsigned_to_string)

    @property
    def unsigned_to_string(self):
        tx_dict = self.to_dict()
        tx_string = tx_dict['sender'] + tx_dict['recipient'] + str(tx_dict['value']) + str(tx_dict['time'])
        return tx_string
        
    @property
    def signed_to_string(self):
        tx_dict = self.to_dict()
        tx_string = tx_dict['sender'] + tx_dict['recipient'] + str(tx_dict['value']) + str(tx_dict['time']) + tx_dict['signature'] + tx_dict['pub_key']
        return tx_string

    def to_dict(self):
        return collections.OrderedDict({
          'sender': self.sender,
          'recipient': self.recipient,
          'value': self._value,
          'time' : self._time,
          'signature': self.signature,
          'pub_key': self.pub_key})
          
    def print_transaction_data(self):
        tx_dict = self.to_dict()
        print('Sender       : ' + tx_dict['sender'])
        print('Recipient    : ' + tx_dict['recipient'])
        print('Value        : ' + str(tx_dict['value']))
        print('Created      : ' + str(tx_dict['time']))
        print('Signature    : ' + tx_dict['signature'])
        print('Pub key      : ' + tx_dict['pub_key'])

    # TODO: BONUS
    # Implement UTXO logic so that each TX is dependant on a previous TX 
    # and each TX is locked to a pubkey hash so that only a corresponding pubkey can spend the TX by satisfying the locking script
    # You will need to also implement the locking and unlocking script logic from Week 2


class Utils:
    @staticmethod    
    def sha256(message):
        # TODO Implement double sha256
        return # TODO 

    @staticmethod
    def base58encode(pub_key_hash):
        # TODO: Implement a base58 encode function to generate an address from a public key hash
    
    @staticmethod
    def verify_signature(signature, pub_key, message):
        # Get signature in a format we can use to verify
        signature_b64_decoded_bytes = base64.b64decode(bytes(signature.encode('UTF-8')))
        if '' == signature or '' == pub_key:
            raise Exception('No signature, public key combination provided')
        # TODO Import the public key as the ecdsa VerifyingKey from the decoded bytes above
        imported_public_key = #TODO


        ###
        # TODO
        # Encode and hash the tx message
        # Then verify sig with ecdsa
        ### 

        hash = #TODO

        try:
            #TODO Verify signature
            return True
        except:
            return False

    @staticmethod
    def verify_pow(block, difficulty=1):
        # TODO: Implement proof of work verification function, i.e. taht a given block hash satisfies the current netwrok difficulty
        prefix = # TODO
        digest = # TODO
        if digest.startswith(prefix):
            return True
        else:
            return False


class Network:
    def __init__(self, difficulty = 1):
        self.difficulty = difficulty
        
    def print_network_data(self, node):
        info = 'NETWORK INFO (at block height ' + str(node.get_block_count) + ')'
        print('\n' + str('=' * len(info)))
        print('' + info)
        print('=' * len(info))
        print('Blockcount    : ' + str(node.get_block_count))
        print('Mempool depth : ' + str(node.get_mempool_count))


def log(message):
    if debug_log:
        print(message)


# Run example
# -----------
print('\n  +-------------------------------------------------------------------+')
print(  '  |                                                                   |')
print(  '  |  A little example of Bitcoin blockchain basics written in Python  |')
print(  '  |                                                                   |')
print(  '  +-------------------------------------------------------------------+')

# Set to false to see less verbose logging:
debug_log = True

utils = Utils()

# Create two node instances that we will use to send and receive our imagined
# blockchain coins
node_1 = Node('Alice Node')
node_2 = Node('Bob Node')

# The network difficuly defines how many leading zeros must prefix a block hash
# for it to be considered valid
network = Network(difficulty = 2)

# Create genesis block with one transaction that pays mining reward to Bob
# We don't have the concept of a utxo set in this example code yet so we allow
# spends from any wallet, even if it doesn't hold any coins
# TODO: BONUS Implement the concept of UTXOs and Coinbase transactions (block reward = block subsidy + fees)

t = Transaction (
    sender = node_1.wallet_id, # Sender is a pub key hash
    recipient = #TODO: recipient should be a base58 encoded address of the recipients PKH
    value = 50.0
)

# The sender needs to sign the transaction using their private key
# TODO

# The signed transaction is added to the mempool - a collection of transactions
# waiting to be added to a block
# TODO

# To view a transaction's data:
t.print_transaction_data()

# We need a dummy block that we can use to provided the 'previous block hash'
# value for our genesis block
block = Block()
block._block_hash = Utils.sha256('Chancellor on brink of second bailout for banks')

# Create the genesis block by mining at the current network difficulty
# Adding transactions to a block should remove them from the mempool
block = node_1.generate_block(block, network.difficulty)

# Apeend the valid block to the node's copy of the blockchain
node_1.append_block(block)

# Create some more transactions ready to be added to a new block. Each 
# transaction needs to be signed by the sender's wallet using the id, 
# which is a base64 encoded public key

# TODO

# Increase the network difficulty to show how it affects block mining and
# the resulting block hash that is found
network.difficulty += 1

block = node_1.generate_block(block, network.difficulty)
node_1.append_block(block)

# To view the transactions in a block:
block.print_transaction_ids()

# View the 'network' data for a given node's view
network.print_network_data(node_1)

# Validate the blockchain - including transaction signatures
node_1.validate_entire_blockchain()

# To view a node's blockchain data (including tx data):
node_1.print_blockchain_data(True)

print('\nExample completed without errors.\n')
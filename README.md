# AIBlock Python SDK

Python SDK for interacting with the AIBlock blockchain. This SDK provides a simple interface for wallet operations and blockchain queries.

## Installation

```bash
pip install aiblock
```

## Quick Start

### Configuration Setup

The SDK uses environment variables for configuration:

```bash
# Required environment variables
export AIBLOCK_PASSPHRASE="your-secure-passphrase"

# Optional environment variables (defaults shown)
export AIBLOCK_STORAGE_HOST="https://storage.aiblock.dev"
export AIBLOCK_MEMPOOL_HOST="https://mempool.aiblock.dev"
export AIBLOCK_VALENCE_HOST="https://valence.aiblock.dev"
```

### Basic Usage

```python
from aiblock.wallet import Wallet
from aiblock.blockchain import BlockchainClient
from aiblock.config import get_config, validate_env_config

# Get and validate configuration
config = get_config()
error = validate_env_config(config)
if error:
    print(f"Configuration error: {error}")
    exit(1)

# Initialize blockchain client
blockchain_client = BlockchainClient(
    storage_host=config['storageHost'],
    mempool_host=config['mempoolHost']
)

# Create and initialize wallet
wallet = Wallet()
seed_phrase = wallet.generate_seed_phrase()
keypair = wallet.generate_keypair()

# Query blockchain
latest_block = blockchain_client.get_latest_block()
total_supply = blockchain_client.get_total_supply()
issued_supply = blockchain_client.get_issued_supply()
balance = blockchain_client.get_balance(keypair['address'])
```

## Features

### Wallet Operations
- Generate and manage seed phrases
- Create and manage keypairs
- Create and sign transactions
- Create item assets
- Check balances

### Blockchain Operations
- Query latest block
- Get block by number
- Get blockchain entry by hash
- Get total supply
- Get issued supply
- Get balance for address

## Example Usage

See the [documentation](https://github.com/AIBlockOfficial/2Way.py/tree/main/docs) for more advanced usage and examples, including:
- Wallet initialization
- Keypair generation
- Blockchain queries
- Asset creation
- Transaction creation
- 2WayPayment protocol

## Development

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Install test dependencies: `pip install -r requirements-test.txt`
4. Run tests: `pytest`

## Contributing

We welcome contributions! Please feel free to submit a Pull Request.

## License

MIT License

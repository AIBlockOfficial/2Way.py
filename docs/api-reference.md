# AIBlock SDK API Reference

## Configuration

The SDK requires a configuration dictionary for connecting to the AIBlock network:

```python
config = {
    'passphrase': 'your-secure-passphrase',
    'storageHost': 'https://storage.aiblock.dev',
    'mempoolHost': 'https://mempool.aiblock.dev',
    'valenceHost': 'https://valence.aiblock.dev'
}
```

## BlockchainClient

The `BlockchainClient` class provides methods for interacting with the AIBlock blockchain.

### Initialization

```python
from aiblock.blockchain import BlockchainClient

# Initialize with configuration
client = BlockchainClient(
    storage_host=config['storageHost'],
    mempool_host=config['mempoolHost']
)
```

The main interface for interacting with the AIBlock blockchain network.

### Configuration

The SDK automatically loads environment variables from a `.env` file in your project directory:

```env
STORAGE_HOST=https://storage.aiblock.dev
MEMPOOL_HOST=https://mempool.aiblock.dev
VALENCE_HOST=https://valence.aiblock.dev
AIBLOCK_PASSPHRASE=your-secure-passphrase
```

If you prefer, you can also set these variables directly in your system environment.

### Read-Only Operations

The BlockchainClient can be used without a wallet for read-only operations:

```python
from aiblock.blockchain import BlockchainClient

# Initialize client for read-only operations (environment variables loaded automatically)
client = BlockchainClient()

# Query blockchain information
total_supply = client.get_total_supply()
issued_supply = client.get_issued_supply()
latest_block = client.get_latest_block()

# Query specific addresses or transactions
balance = client.get_balance("some_address")
transaction = client.get_transaction("transaction_hash")
```

Available read-only operations:
- `get_total_supply()`: Get total token supply
- `get_issued_supply()`: Get issued token supply
- `get_latest_block()`: Get the latest block information
- `get_balance(address)`: Get balance for an address
- `get_transaction(tx_hash)`: Get transaction details

### Write Operations

Write operations (creating assets, sending transactions) require a wallet:

```python
from aiblock.wallet import Wallet

wallet = Wallet()
response = client.create_item_asset(
    to_address=wallet.address,
    amount=1,
    metadata={"type": "example"}
)
```

### Constructor

```python
BlockchainClient(
    storage_host: str = None,
    mempool_host: str = None,
    valence_host: str = None
)
```

- `storage_host`: URL of the storage node (optional, defaults to STORAGE_HOST environment variable)
- `mempool_host`: URL of the mempool node (optional, defaults to MEMPOOL_HOST environment variable)
- `valence_host`: URL of the valence node (optional, defaults to VALENCE_HOST environment variable)

If parameters are not provided, the constructor will automatically use values from environment variables.

### Methods

#### get_total_supply()
Returns the total token supply of the blockchain.

```python
response = client.get_total_supply()
total = response['content']['content']
```

Returns:
```python
{
    "status": "success",
    "content": {
        "id": str,
        "status": "Success",
        "reason": str,
        "route": "total_supply",
        "content": int  # Total supply in smallest units
    }
}
```

#### get_issued_supply()
Returns the current issued token supply.

```python
response = client.get_issued_supply()
issued = response['content']['content']
```

Returns:
```python
{
    "status": "success",
    "content": {
        "id": str,
        "status": "Success",
        "reason": str,
        "route": "issued_supply",
        "content": int  # Issued supply in smallest units
    }
}
```

#### create_item_asset()
Creates a new non-fungible item asset.

```python
response = client.create_item_asset(
    to_address: str,
    amount: int,
    metadata: dict,
    genesis_hash: str = "default_genesis_hash"
)
```

Parameters:
- `to_address`: Destination address for the item
- `amount`: Quantity of items to create
- `metadata`: JSON metadata describing the item
- `genesis_hash`: Optional genesis hash for the item

Returns:
```python
{
    "status": "success",
    "content": {
        "asset": {
            "Item": {
                "amount": int,
                "genesis_hash": str,
                "metadata": str  # JSON string
            }
        },
        "to_address": str,
        "tx_hash": str
    }
}
```

## Wallet

Manages cryptographic keys and blockchain addresses.

### Constructor

```python
Wallet(seed_phrase: str = None)
```

- `seed_phrase`: Optional BIP39 seed phrase for wallet initialization

### Methods

#### generate_seed_phrase()
Generates a new BIP39 seed phrase.

```python
seed_phrase = wallet.generate_seed_phrase()
```

Returns: `str` - 12-word BIP39 seed phrase

#### get_address()
Returns the wallet's blockchain address.

```python
address = wallet.get_address()
```

Returns: `str` - Base58-encoded address

#### sign_message()
Signs a message with the wallet's private key.

```python
signature = wallet.sign_message(message: bytes)
```

Parameters:
- `message`: Bytes to sign

Returns: `str` - Base58-encoded signature

## Error Handling

The SDK uses a consistent error format:

```python
{
    "status": "error",
    "reason": str,  # Human-readable error description
    "error_code": str  # Machine-readable error code
}
```

Common error codes:
- `INSUFFICIENT_BALANCE`
- `INVALID_ADDRESS`
- `NETWORK_ERROR`
- `INVALID_METADATA`

## Type Hints

The SDK provides comprehensive type hints for better IDE integration:

```python
from aiblock.interfaces import (
    BlockResponse,
    SupplyResponse,
    AssetResponse,
    TransactionResponse
)
```

## Best Practices

1. Always check response status:
```python
response = client.create_item_asset(...)
if response['status'] == 'success':
    # Handle success
else:
    # Handle error
```

2. Use try-catch for error handling:
```python
try:
    response = client.create_item_asset(...)
except Exception as e:
    # Handle network or other errors
```

3. Validate inputs before sending:
```python
def validate_metadata(metadata: dict) -> bool:
    try:
        # Ensure metadata is JSON serializable
        json.dumps(metadata)
        return True
    except Exception:
        return False
``` 
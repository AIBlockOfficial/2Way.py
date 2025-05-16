# AIBlock SDK Examples

This document provides practical examples of using the AIBlock SDK in AI-focused applications.

## AI Model Management

### Storing Model Checkpoints as NFTs

```python
from aiblock.wallet import Wallet
from aiblock.blockchain import BlockchainClient
import json
import hashlib

def save_model_checkpoint(model_path: str, metadata: dict, client: BlockchainClient, wallet: Wallet):
    # Calculate model hash
    with open(model_path, 'rb') as f:
        model_hash = hashlib.sha256(f.read()).hexdigest()
    
    # Prepare metadata
    checkpoint_metadata = {
        "type": "model_checkpoint",
        "name": metadata.get("name", "Unnamed Model"),
        "version": metadata.get("version", "1.0"),
        "description": metadata.get("description", ""),
        "model_hash": model_hash,
        "architecture": metadata.get("architecture", {}),
        "training_params": metadata.get("training_params", {}),
        "performance_metrics": metadata.get("performance_metrics", {}),
        "timestamp": metadata.get("timestamp", "")
    }
    
    # Create NFT for the checkpoint
    response = client.create_item_asset(
        to_address=wallet.address,
        amount=1,
        metadata=checkpoint_metadata
    )
    
    return response

# Usage example
config = {
    'storageHost': 'https://storage.aiblock.dev',
    'mempoolHost': 'https://mempool.aiblock.dev',
    'valenceHost': 'https://valence.aiblock.dev'
}
client = BlockchainClient(storage_host=config['storageHost'], mempool_host=config['mempoolHost'])
wallet = Wallet()

metadata = {
    "name": "BERT-Large Fine-tuned",
    "version": "2.0",
    "description": "BERT model fine-tuned on custom dataset",
    "architecture": {
        "type": "transformer",
        "hidden_size": 1024,
        "num_layers": 24,
        "num_heads": 16
    },
    "training_params": {
        "epochs": 10,
        "batch_size": 32,
        "learning_rate": 2e-5,
        "optimizer": "AdamW"
    },
    "performance_metrics": {
        "accuracy": 0.92,
        "f1_score": 0.89,
        "precision": 0.90,
        "recall": 0.88
    },
    "timestamp": "2024-03-25T15:30:00Z"
}

response = save_model_checkpoint(
    "path/to/model.pt",
    metadata,
    client,
    wallet
)
```

### Dataset Management

```python
def register_dataset(dataset_path: str, metadata: dict, client: BlockchainClient, wallet: Wallet):
    # Calculate dataset hash
    with open(dataset_path, 'rb') as f:
        dataset_hash = hashlib.sha256(f.read()).hexdigest()
    
    # Prepare metadata
    dataset_metadata = {
        "type": "dataset",
        "name": metadata.get("name", "Unnamed Dataset"),
        "version": metadata.get("version", "1.0"),
        "description": metadata.get("description", ""),
        "dataset_hash": dataset_hash,
        "schema": metadata.get("schema", {}),
        "statistics": metadata.get("statistics", {}),
        "license": metadata.get("license", ""),
        "timestamp": metadata.get("timestamp", "")
    }
    
    # Create NFT for the dataset
    response = client.create_item_asset(
        to_address=wallet.address,
        amount=1,
        metadata=dataset_metadata
    )
    
    return response

# Usage example
dataset_metadata = {
    "name": "Large Language Model Training Dataset",
    "version": "1.0",
    "description": "Curated dataset for language model training",
    "schema": {
        "fields": ["text", "label", "source"],
        "types": ["string", "int", "string"]
    },
    "statistics": {
        "num_samples": 1000000,
        "num_classes": 10,
        "class_distribution": {
            "0": 0.1,
            "1": 0.1,
            # ... other classes
        }
    },
    "license": "CC BY-SA 4.0",
    "timestamp": "2024-03-25T15:30:00Z"
}

response = register_dataset(
    "path/to/dataset.csv",
    dataset_metadata,
    client,
    wallet
)
```

### Model Marketplace Integration

```python
def list_model_for_sale(
    model_metadata: dict,
    price: int,
    client: BlockchainClient,
    wallet: Wallet
):
    # Prepare marketplace metadata
    marketplace_metadata = {
        "type": "ai_model_listing",
        "model_info": model_metadata,
        "price": price,
        "seller": wallet.address,
        "status": "active",
        "timestamp": "2024-03-25T15:30:00Z"
    }
    
    # Create marketplace listing as NFT
    response = client.create_item_asset(
        to_address=wallet.address,
        amount=1,
        metadata=marketplace_metadata
    )
    
    return response

# Usage example
model_metadata = {
    "name": "GPT-4 Fine-tuned for Medical Text",
    "version": "1.0",
    "description": "Specialized language model for medical text analysis",
    "capabilities": [
        "Medical text understanding",
        "Disease classification",
        "Treatment recommendation"
    ],
    "performance_metrics": {
        "accuracy": 0.95,
        "precision": 0.94,
        "recall": 0.93,
        "f1_score": 0.94
    },
    "training_details": {
        "base_model": "GPT-4",
        "fine_tuning_steps": 10000,
        "dataset_size": "1M medical records"
    },
    "requirements": {
        "compute": "16GB GPU",
        "memory": "32GB RAM",
        "disk": "100GB SSD"
    }
}

# List model for 1000 tokens
response = list_model_for_sale(
    model_metadata,
    1000,
    client,
    wallet
)
```

### Model Verification and Provenance

```python
def verify_model_authenticity(
    model_path: str,
    blockchain_hash: str,
    client: BlockchainClient
) -> bool:
    # Calculate current model hash
    with open(model_path, 'rb') as f:
        current_hash = hashlib.sha256(f.read()).hexdigest()
    
    # Compare with blockchain record
    return current_hash == blockchain_hash

def track_model_lineage(
    base_model_hash: str,
    training_data_hash: str,
    new_model_metadata: dict,
    client: BlockchainClient,
    wallet: Wallet
):
    # Prepare lineage metadata
    lineage_metadata = {
        "type": "model_lineage",
        "base_model": base_model_hash,
        "training_data": training_data_hash,
        "derived_model": new_model_metadata,
        "timestamp": "2024-03-25T15:30:00Z"
    }
    
    # Create lineage record as NFT
    response = client.create_item_asset(
        to_address=wallet.address,
        amount=1,
        metadata=lineage_metadata
    )
    
    return response

# Usage example
new_model_metadata = {
    "name": "GPT-4 Medical Specialist",
    "version": "2.0",
    "description": "Enhanced medical text model",
    "changes": [
        "Fine-tuned on additional medical datasets",
        "Improved rare disease recognition",
        "Enhanced medical terminology understanding"
    ]
}

response = track_model_lineage(
    "base_model_hash_from_blockchain",
    "training_data_hash_from_blockchain",
    new_model_metadata,
    client,
    wallet
)
```

## Best Practices for AI Applications

1. **Versioning**: Always include detailed version information in metadata
2. **Reproducibility**: Store all hyperparameters and training configurations
3. **Provenance**: Maintain clear lineage of model derivatives
4. **Performance Metrics**: Include comprehensive evaluation metrics
5. **Resource Requirements**: Specify computational requirements clearly
6. **Documentation**: Maintain detailed documentation of model capabilities and limitations

## Error Handling in AI Workflows

```python
def safe_ai_operation(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            # Log error
            print(f"Error in AI operation: {str(e)}")
            # Return standardized error response
            return {
                "status": "error",
                "reason": str(e),
                "error_code": "AI_OPERATION_FAILED"
            }
    return wrapper

@safe_ai_operation
def process_ai_model(model_path: str, client: BlockchainClient):
    # AI model processing logic here
    pass
``` 
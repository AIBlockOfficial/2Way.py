"""Client for interacting with the AIBlock blockchain."""

from __future__ import annotations

import requests
import logging
from typing import TypedDict, Literal, Optional, Dict, Any
from enum import Enum
import uuid
import random
from urllib.parse import urlparse
from aiblock.interfaces import IResult, IErrorInternal

# Set up logging
logger = logging.getLogger(__name__)

# Type definitions
ResponseStatus = Literal['success', 'error', 'pending', 'unknown']

class ResponseContent(TypedDict, total=False):
    """Content type for API responses."""
    block_num: int
    block_hash: str
    timestamp: int
    transactions: list
    previous_hash: str
    total_supply: str
    issued_supply: str

class APIResponse(TypedDict):
    """Standard API response type."""
    id: str
    status: ResponseStatus
    reason: str
    content: Optional[ResponseContent]

def get_random_string(length: int) -> str:
    """Generate a random string of specified length."""
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return ''.join(random.choice(chars) for _ in range(length))

def get_headers() -> Dict[str, str]:
    """Get headers for API requests."""
    return {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Request-ID': str(uuid.uuid4()),
        'Nonce': get_random_string(32)
    }

def create_response(
    status: ResponseStatus,
    reason: str,
    content: Optional[ResponseContent] = None
) -> APIResponse:
    """Create a standardized API response."""
    return {
        'id': str(uuid.uuid4()),
        'status': status,
        'reason': reason,
        'content': content
    }

def handle_response(response) -> IResult[APIResponse]:
    """Handle API response and return standardized format.

    Args:
        response: The response object from the API request.

    Returns:
        IResult[APIResponse]: A result containing:
            - id (str): A unique identifier for the response
            - status (str): The status of the response (Success, error, pending, unknown)
            - reason (str): A human-readable message explaining the status
            - content (dict, optional): The response content for successful requests
    """
    # Generate a unique ID for this response
    response_id = str(uuid.uuid4())

    # Extract the endpoint from the URL
    path = urlparse(str(response.url)).path.strip('/')
    endpoint = path.split('/')[0] if path else ''

    # Define success messages for different endpoints
    success_messages = {
        'latest_block': 'Latest block retrieved successfully',
        'block': 'Block retrieved successfully',
        'blockchain': 'Blockchain entry retrieved successfully',
        'total_supply': 'Total supply retrieved successfully',
        'issued_supply': 'Issued supply retrieved successfully'
    }

    try:
        if response.status_code == 200:
            try:
                content = response.json()
                return IResult.ok({
                    'id': response_id,
                    'status': 'success',
                    'reason': success_messages.get(endpoint, 'Operation completed successfully'),
                    'content': content.get('content', content)
                })
            except ValueError:
                return IResult.err(IErrorInternal.InvalidParametersProvided, 'Invalid JSON response')
        elif response.status_code == 400:
            return IResult.err(IErrorInternal.BadRequest, response.text or 'Bad request')
        elif response.status_code == 401:
            return IResult.err(IErrorInternal.Unauthorized, response.text or 'Unauthorized')
        elif response.status_code == 403:
            return IResult.err(IErrorInternal.Forbidden, response.text or 'Forbidden')
        elif response.status_code == 404:
            return IResult.err(IErrorInternal.NotFound, response.text or 'Resource not found')
        elif response.status_code == 405:
            return IResult.err(IErrorInternal.BadRequest, response.text or 'Method not allowed')
        elif response.status_code == 202:
            return IResult.err(IErrorInternal.InvalidParametersProvided, response.text or 'Request is being processed')
        elif response.status_code == 500:
            return IResult.err(IErrorInternal.InternalServerError, response.text or 'Internal server error')
        elif response.status_code == 503:
            return IResult.err(IErrorInternal.ServiceUnavailable, response.text or 'Service unavailable')
        elif response.status_code == 504:
            return IResult.err(IErrorInternal.GatewayTimeout, response.text or 'Gateway timeout')
        elif response.status_code >= 500:
            return IResult.err(IErrorInternal.InternalServerError, f'Server error: {response.text}')
        else:
            return IResult.err(IErrorInternal.UnknownError, f'Unknown error: {response.text}')
    except requests.exceptions.ConnectionError:
        return IResult.err(IErrorInternal.NetworkError, 'Network error occurred')
    except Exception as e:
        return IResult.err(IErrorInternal.InternalError, f'Error processing response: {str(e)}')

class BlockchainClient:
    """Client for interacting with the AIBlock blockchain."""
    
    def __init__(self, storage_host: str, mempool_host: Optional[str] = None) -> None:
        """Initialize the blockchain client.
        
        Args:
            storage_host: URL of the storage node
            mempool_host: Optional URL of the mempool node
            
        Raises:
            ValueError: If storage_host is None
        """
        if storage_host is None:
            raise ValueError("storage_host cannot be None")
        self.storage_host = storage_host
        self.mempool_host = mempool_host

    def _validate_storage_host(self) -> None:
        """Validate storage_host."""
        if self.storage_host is None:
            raise ValueError("storage_host cannot be None")

    def _make_request(
        self,
        endpoint: str,
        host_type: Literal['storage', 'mempool'] = 'storage'
    ) -> IResult[APIResponse]:
        """Make an API request with error handling."""
        host = self.mempool_host if host_type == 'mempool' else self.storage_host
        if not host:
            return IResult.err(IErrorInternal.InvalidParametersProvided, f'{host_type.title()} host not initialized')

        try:
            response = requests.get(f"{host}/{endpoint}", headers=get_headers())
            return handle_response(response)
        except requests.RequestException as e:
            return IResult.err(IErrorInternal.NetworkError, f'Network error: {str(e)}')

    def get_latest_block(self) -> IResult[APIResponse]:
        """Get the latest block from the blockchain."""
        return self._make_request('latest_block')

    def get_block_by_num(self, block_num: int) -> IResult[APIResponse]:
        """Get a block by its number.

        Args:
            block_num: Block number to retrieve

        Returns:
            IResult[APIResponse] containing:
                - id: Unique identifier for this response
                - status: 'success', 'error', 'pending', or 'unknown'
                - reason: Human readable explanation
                - content: Block data if successful

        Raises:
            ValueError: If storage_host is None
        """
        self._validate_storage_host()
        return self._make_request(f'block/{block_num}')

    def get_blockchain_entry(self, block_hash: str) -> IResult[APIResponse]:
        """Get a blockchain entry by hash.

        Args:
            block_hash: Hash of the block to retrieve

        Returns:
            IResult[APIResponse] containing:
                - id: Unique identifier for this response
                - status: 'success', 'error', 'pending', or 'unknown'
                - reason: Human readable explanation
                - content: Block data if successful

        Raises:
            ValueError: If storage_host is None
        """
        self._validate_storage_host()
        return self._make_request(f'blockchain/{block_hash}')

    def get_total_supply(self) -> IResult[APIResponse]:
        """Get the total supply of tokens.

        Returns:
            IResult[APIResponse]: A result containing the total supply information.
        """
        if not self.mempool_host:
            return IResult.err(IErrorInternal.InvalidParametersProvided, "Mempool URL not set")
        return self._make_request('total_supply', host_type='mempool')

    def get_issued_supply(self) -> IResult[APIResponse]:
        """Get the issued supply of tokens.

        Returns:
            IResult[APIResponse]: A result containing the issued supply information.
        """
        if not self.mempool_host:
            return IResult.err(IErrorInternal.InvalidParametersProvided, "Mempool URL not set")
        return self._make_request('issued_supply', host_type='mempool')
import requests

from key_handler import get_passphrase_buffer, generate_master_key
from utils import (
    cast_api_status,
    create_id_and_nonce_headers,
    throw_if_err,
    transform_create_tx_response_from_network,
)
from utils.valence_utils import generate_valence_set_body, generate_verification_headers
from constants import ADDRESS_VERSION, ITEM_DEFAULT, SEED_REGEN_THRES

class Wallet:
    def __init__(self):
        self.mempool_host = None
        self.storage_host = None
        self.valence_host = None
        self.key_mgmt = None
        self.mempool_routes_pow = None
        self.storage_routes_pow = None

    def init_new(self, config, init_offline=False):
        valid = validate_config(config)
        if valid.error:
            return handle_validation_failures([valid.error])

        self.key_mgmt = KeyMgmt()
        init_result = self.key_mgmt.init_new(config['passphrase'])

        if not init_offline:
            init_network_result = self.init_network(config)
            if init_network_result['status'] == 'error':
                return init_network_result

        if init_result.is_err():
            return {
                'status': 'error',
                'reason': init_result.error,
            }
        else:
            return {
                'status': 'success',
                'reason': 'ClientInitialized',
                'content': {
                    'initNewResponse': init_result.value,
                },
            }

    def from_master_key(self, master_key, config, init_offline=False):
        init_result = self.key_mgmt.from_master_key(master_key, config['passphrase'])

        if not init_offline:
            init_network_result = self.init_network(config)
            if init_network_result['status'] == 'error':
                return init_network_result

        if init_result.is_err():
            return {
                'status': 'error',
                'reason': init_result.error,
            }
        else:
            return {
                'status': 'success',
                'reason': 'ClientInitialized',
            }

    def from_seed(self, seed_phrase, config, init_offline=False):
        passphrase = get_passphrase_buffer(config.passphrase)
        if passphrase.is_err():
            return IResult.err(passphrase.error)
        self.passphrase_key = passphrase.value

        new_master_key = generate_master_key(seed_phrase)
        if new_master_key.is_err():
            return IResult.err(new_master_key.error)
        self.master_key = new_master_key.value

        save_result = self.encrypt_master_key(new_master_key.value, passphrase.value)
        if save_result.is_err():
            return IResult.err(save_result.error)

        self.seed_phrase = seed_phrase

        if not init_offline:
            init_network_result = self.init_network(config)
            if init_network_result['status'] == 'error':
                return init_network_result

        if init_result.is_err():
            return {
                'status': 'error',
                'reason': init_result.error,
            }

        return {
            'status': 'success',
            'reason': 'ClientInitialized',
            'content': {
                'fromSeedResponse': init_result.value,
            },
        }

    def init_network(self, config):
        valid_config = validate_config(config)
        if valid_config.error:
            return handle_validation_failures([valid_config.error])

        self.mempool_host = config.get('mempoolHost')
        self.storage_host = config.get('storageHost')
        self.valence_host = config.get('valenceHost')

        if not self.mempool_host:
            return {
                'status': 'error',
                'reason': 'NoComputeHostProvided',
            }

        self.mempool_routes_pow = {}
        init_compute_result = self.init_network_for_host(self.mempool_host, self.mempool_routes_pow)
        if init_compute_result['status'] == 'error':
            return init_compute_result

        if self.storage_host:
            self.storage_routes_pow = {}
            init_storage_result = self.init_network_for_host(self.storage_host, self.storage_routes_pow)
            if init_storage_result['status'] == 'error':
                return init_storage_result

        if not any([self.mempool_host, self.storage_host, self.valence_host]):
            return {
                'status': 'error',
                'reason': 'NoHostsProvided',
            }

        return {'status': 'success'}
    

    def fetch_balance(self, address_list):
        valid_addresses = [validate_address(address) for address in address_list]
        if any(address.error for address in valid_addresses):
            return handle_validation_failures([address.error for address in valid_addresses])

        try:
            if not all([self.mempool_host, self.key_mgmt, self.mempool_routes_pow]):
                raise Exception('ClientNotInitialized')
            headers = self.get_request_id_and_nonce_headers_for_route(
                self.mempool_routes_pow, '/fetch_balance'
            )
            response = requests.post(
                f"{self.mempool_host}/fetch_balance", json=address_list, headers=headers
            )
            return {
                'status': cast_api_status(response.json()['status']),
                'reason': response.json().get('reason'),
                'content': {
                    'fetchBalanceResponse': response.json().get('content'),
                },
            }
        except Exception as error:
            return {
                'status': 'error',
                'reason': str(error),
            }

    def create_items(self, address, default_genesis_hash=True, amount=ITEM_DEFAULT, metadata=None):
        valid_metadata = validate_metadata(metadata) if metadata else {'error': None}
        if valid_metadata.error:
            return handle_validation_failures([valid_metadata.error])

        try:
            if not all([self.mempool_host, self.key_mgmt, self.mempool_routes_pow]):
                raise Exception('ClientNotInitialized')
            keypair = throw_if_err(self.key_mgmt.decrypt_keypair(address))
            create_item_body = throw_if_err(
                create_item_payload(
                    keypair.secret_key, keypair.public_key, keypair.version, amount,
                    default_genesis_hash, metadata
                )
            )
            headers = self.get_request_id_and_nonce_headers_for_route(
                self.mempool_routes_pow, '/create_item_asset'
            )
            response = requests.post(
                f"{self.mempool_host}/create_item_asset", json=create_item_body, headers=headers
            )
            return {
                'status': cast_api_status(response.json()['status']),
                'reason': response.json().get('reason'),
                'content': {
                    'createItemResponse': response.json().get('content'),
                },
            }
        except Exception as error:
            return {
                'status': 'error',
                'reason': str(error),
            }

    # Additional methods follow the same pattern

    def get_request_id_and_nonce_headers_for_route(self, routes_pow, route):
        if not routes_pow:
            raise Exception('ClientNotInitialized')
        route_difficulty = routes_pow.get(route.lstrip('/'))
        return {
            'x-cache-id': generate_cache_id(),
            'x-nonce': generate_nonce(route_difficulty),
            **DEFAULT_HEADERS,
        }

    def init_network_for_host(self, host, routes_pow):
        debug_data = self.get_debug_data(host)
        if debug_data['status'] == 'error':
            return debug_data
        for route, pow in debug_data['content']['debugDataResponse']['routes_pow'].items():
            routes_pow[route] = pow
        return {'status': 'success'}

    def get_debug_data(self, host):
        valid_host = validate_url(host)
        if valid_host.error:
            return handle_validation_failures([valid_host.error])

        try:
            response = requests.get(f"{host}/debug_data")
            return {
                'status': cast_api_status(response.json()['status']),
                'reason': response.json().get('reason'),
                'content': {
                    'debugDataResponse': response.json().get('content'),
                },
            }
        except Exception as error:
            return {
                'status': 'error',
                'reason': str(error),
            }

# You can add additional methods following the same pattern, adjusting them according to your needs

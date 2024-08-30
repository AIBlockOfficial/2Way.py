from mnemonic import Mnemonic
from byte_base64 import bytes_to_base64
from sha3 import sha3_256
import nacl.signing
import uuid
from nacl.exceptions import BadSignatureError

from interfaces import IErrorInternal, IKeypair, IMasterKey, IResult
from utils.general_utils import (
    get_hex_string_bytes,
    get_string_bytes,
    throw_if_err,
    truncate_by_bytes_utf8,
)
from constants import ADDRESS_VERSION, ADDRESS_VERSION_OLD, TEMP_ADDRESS_VERSION

def get_address_version(public_key: bytes = None, address: str = None, version: int = None) -> IResult[int]:
    if public_key and address:
        temp_address = construct_address(public_key, TEMP_ADDRESS_VERSION)
        if temp_address.is_err():
            return temp_address
        default_address = construct_address(public_key, ADDRESS_VERSION)
        if default_address.is_err():
            return default_address
        if address == temp_address.value:
            return IResult.ok(TEMP_ADDRESS_VERSION)
        elif address == default_address.value:
            return IResult.ok(None)
        else:
            return IResult.err(IErrorInternal.InvalidAddressVersion)
    elif version is not None:
        if version == TEMP_ADDRESS_VERSION:
            return IResult.ok(TEMP_ADDRESS_VERSION)
        elif version == ADDRESS_VERSION:
            return IResult.ok(ADDRESS_VERSION)
        else:
            return IResult.err(IErrorInternal.InvalidAddressVersion)
    else:
        return IResult.err(IErrorInternal.InvalidParametersProvided)

def generate_seed() -> IResult[str]:
    try:
        mnemonic = Mnemonic('english')
        seed_phrase = mnemonic.generate()
        return IResult.ok(seed_phrase)
    except Exception:
        return IResult.err(IErrorInternal.UnableToGenerateSeed)

def get_passphrase_buffer(passphrase: str) -> IResult[bytes]:
    if passphrase is None:
        return IResult.err(IErrorInternal.NoPassPhraseProvided)
    try:
        hash_val = sha3_256(passphrase.encode('utf-8')).hexdigest()
        truncated_val = truncate_by_bytes_utf8(hash_val, 32)
        return IResult.ok(get_string_bytes(truncated_val))
    except Exception:
        return IResult.err(IErrorInternal.UnableToGetPassphraseBuffer)

def generate_master_key(seed: str = None, passphrase: str = None) -> IResult[IMasterKey]:
    try:
        mnemonic = Mnemonic('english')
        if seed:
            mnemonic.verify(seed)  # Verify if the provided seed is valid
        else:
            seed = mnemonic.generate()

        hd_private_key = mnemonic.to_hd_private_key(seed, passphrase)
        return IResult.ok(IMasterKey(
            secret=hd_private_key,
            seed=seed
        ))
    except Exception:
        return IResult.err(IErrorInternal.InvalidSeedPhrase)

def generate_keypair(version: int = ADDRESS_VERSION, seed: bytes = None) -> IResult[IKeypair]:
    try:
        if seed and len(seed) != 32:
            seed = seed[:32]
        keypair_raw = nacl.signing.SigningKey(seed) if seed else nacl.signing.SigningKey.generate()
        address = throw_if_err(construct_address(keypair_raw.verify_key.encode(), version))
        return IResult.ok(IKeypair(
            address=address,
            secret_key=keypair_raw.encode(),
            public_key=keypair_raw.verify_key.encode(),
            version=version
        ))
    except Exception:
        return IResult.err(IErrorInternal.UnableToGenerateKeypair)

def get_next_derived_keypair(master_key: IMasterKey, depth: int, version: int = ADDRESS_VERSION) -> IResult[IKeypair]:
    try:
        seed_key_raw = master_key.secret.derive_child(depth, True)
        seed_key = get_string_bytes(seed_key_raw.xprivkey)
        return generate_keypair(version, seed_key)
    except Exception:
        return IResult.err(IErrorInternal.UnableToDeriveNextKeypair)

def construct_address(public_key: bytes, version: int = None) -> IResult[str]:
    if version == ADDRESS_VERSION_OLD:
        return construct_version_old_address(public_key)
    elif version == TEMP_ADDRESS_VERSION:
        return construct_version_temp_address(public_key)
    elif version == ADDRESS_VERSION:
        return construct_version_default_address(public_key)
    else:
        return IResult.err(IErrorInternal.InvalidAddressVersion)

def construct_version_old_address(public_key: bytes) -> IResult[str]:
    try:
        array_one = bytes([32, 0, 0, 0, 0, 0, 0, 0])
        merged_array = array_one + public_key
        hash_val = sha3_256(merged_array).hexdigest()
        return IResult.ok(truncate_string(hash_val, len(hash_val) - 16))
    except Exception:
        return IResult.err(IErrorInternal.UnableToConstructDefaultAddress)

def truncate_string(string: str = '', max_length: int = 50) -> str:
    return string[:max_length] if len(string) > max_length else string

def construct_version_default_address(public_key: bytes) -> IResult[str]:
    try:
        return IResult.ok(sha3_256(public_key).hexdigest())
    except Exception:
        return IResult.err(IErrorInternal.UnableToConstructDefaultAddress)

def construct_version_temp_address(public_key: bytes) -> IResult[str]:
    try:
        return IResult.ok(sha3_256(get_hex_string_bytes(bytes_to_base64(public_key))).hexdigest())
    except Exception:
        return IResult.err(IErrorInternal.UnableToConstructTempAddress)

def create_signature(secret_key: bytes, message: bytes) -> bytes:
    signing_key = nacl.signing.SigningKey(secret_key)
    return signing_key.sign(message).signature

def generate_new_keypair_and_address(master_key: IMasterKey, address_version: int = ADDRESS_VERSION, addresses: list = []) -> IResult[IKeypair]:
    counter = len(addresses)
    current_key = get_next_derived_keypair(master_key, counter)
    if current_key.is_err():
        return current_key
    current_addr = construct_address(current_key.value.public_key, address_version)
    if current_addr.is_err():
        return current_addr

    while current_addr.value in addresses:
        counter += 1
        current_key = get_next_derived_keypair(master_key, counter)
        if current_key.is_err():
            return current_key
        current_addr = construct_address(current_key.value.public_key, address_version)
        if current_addr.is_err():
            return current_addr

    return IResult.ok(IKeypair(
        address=current_addr.value,
        secret_key=current_key.value.secret_key,
        public_key=current_key.value.public_key,
        version=address_version
    ))

def test_seed_phrase(seed: str) -> bool:
    return not generate_master_key(seed).is_err()

def generate_seed_phrase() -> str:
    return generate_seed().unwrap_or('')

def encrypt_master_key(self, master_key: IMasterKey, passphrase: bytes = None) -> IResult[IMasterKeyEncrypted]:
        try:
            nonce = truncate_by_bytes_utf8(uuid.uuid4().hex, 24)
            secret_key = get_string_bytes(master_key.secret.xprivkey)
            save = nacl.secret.SecretBox(passphrase or self.passphrase_key).encrypt(secret_key, get_string_bytes(nonce))

            return IResult.ok({
                'nonce': nonce,
                'save': bytes_to_base64(save.ciphertext),
            })
        except Exception:
            return IResult.err(IErrorInternal.UnableToEncryptMasterKey)
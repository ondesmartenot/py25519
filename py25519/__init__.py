from ctypes import (
    CDLL,
    RTLD_GLOBAL,
    byref,
    c_ulonglong,
    create_string_buffer,
    util,
)
from typing import Tuple

librb = CDLL(
    util.find_library("randombytes_kernel")
    or util.find_library("librandombytes_kernel"),
    mode=RTLD_GLOBAL,
)
lib = CDLL(util.find_library("25519") or util.find_library("lib25519"))

if not lib._name:
    raise ValueError("Unable to find lib25519")


def __check(code: int) -> None:
    if code != 0:
        raise ValueError


lib25519_dh_SECRETKEYBYTES = 32
lib25519_dh_PUBLICKEYBYTES = 32
lib25519_dh_BYTES = 32
lib25519_sign_SECRETKEYBYTES = 64
lib25519_sign_PUBLICKEYBYTES = 32
lib25519_sign_BYTES = 64


def dh_keypair() -> Tuple[bytes, bytes]:
    """
    Returns a Curve25519 public and private DH keypair
    Example:

    >>> pk, sk = dh_keypair()
    """
    sk = create_string_buffer(lib25519_dh_SECRETKEYBYTES)
    pk = create_string_buffer(lib25519_dh_PUBLICKEYBYTES)
    lib.lib25519_dh_x25519_keypair(pk, sk)
    return pk.raw, sk.raw


def dh(pk: bytes, sk: bytes) -> bytes:
    """Returns an ECDH secret key from public key pk and secret key sk

    INPUT:
    pk: 32-bytes public key
    sk: 32-bytes private key

    Example:

    >>> pk0, sk0 = dh_keypair()
    >>> pk1, sk1 = dh_keypair()
    >>> assert dh(pk0, sk1) == dh(pk1, sk0)

    """
    if len(pk) != lib25519_dh_PUBLICKEYBYTES:
        raise ValueError
    if len(sk) != lib25519_dh_SECRETKEYBYTES:
        raise ValueError
    sk_arr = create_string_buffer(sk)
    pk_arr = create_string_buffer(pk)
    k = create_string_buffer(lib25519_dh_BYTES)
    lib.lib25519_dh_x25519(k, pk_arr, sk_arr)
    return k.raw


def sign_keypair() -> Tuple[bytes, bytes]:
    """
    Returns a Ed25519 public and private keypair

    Example:

    >>> pk, sk = sign_keypair()
    """
    pk = create_string_buffer(lib25519_sign_PUBLICKEYBYTES)
    sk = create_string_buffer(lib25519_sign_SECRETKEYBYTES)
    lib.lib25519_sign_ed25519_keypair(pk, sk)
    return pk.raw, sk.raw


def sign(m: bytes, sk: bytes) -> bytes:
    """Signs message m with Ed25519 private key sk.

    INPUT:
    m: arbitrary-length message in bytes
    sk: Ed25519 secret key

    Example:

    >>> pk, sk = sign_keypair()
    >>> msg = b"hello"
    >>> signed_msg = sign(msg, sk)

    """
    assert len(sk) == lib25519_sign_SECRETKEYBYTES
    mlen = c_ulonglong(len(m))
    smlen = c_ulonglong(0)
    sm = create_string_buffer(len(m) + lib25519_sign_BYTES)
    m_arr = create_string_buffer(m)
    sk_arr = create_string_buffer(sk)
    lib.lib25519_sign_ed25519(sm, byref(smlen), m_arr, mlen, sk_arr)
    return sm.raw[: smlen.value]


def open_sig(sm: bytes, pk: bytes) -> bytes:
    """verifies a signed message m with Ed25519 private key sk and returns the
    original message if successful.

    INPUT:
    sm: Ed25519 signed message
    pk: Ed25519 public key

    Example:

    >>> pk, sk = sign_keypair()
    >>> msg = b"hello"
    >>> signed_msg = sign(msg, sk)
    >>> assert msg == open_sig(signed_msg, pk)

    """
    assert len(pk) == lib25519_sign_PUBLICKEYBYTES
    smlen = c_ulonglong(len(sm))
    m = create_string_buffer(len(sm))
    mlen = c_ulonglong(0)
    pk_arr = create_string_buffer(pk)
    code = lib.lib25519_sign_ed25519_open(m, byref(mlen), sm, smlen, pk_arr)
    __check(code)
    return m.raw[: mlen.value]

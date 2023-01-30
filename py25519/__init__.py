from ctypes import CDLL, c_ulonglong, byref, create_string_buffer, util, RTLD_GLOBAL

librb = CDLL(util.find_library('randombytes_kernel') or
             util.find_library('librandombytes_kernel'),
             mode=RTLD_GLOBAL)
lib = CDLL(util.find_library('25519') or util.find_library('lib25519'))

if not lib._name:
    raise ValueError('Unable to find lib25519')


def __check(code):
    if code != 0:
        raise ValueError


lib25519_dh_SECRETKEYBYTES = 32
lib25519_dh_PUBLICKEYBYTES = 32
lib25519_dh_BYTES = 32
lib25519_sign_SECRETKEYBYTES = 64
lib25519_sign_PUBLICKEYBYTES = 32
lib25519_sign_BYTES = 64


def dh_keypair() -> (bytes, bytes):
    """
    Returns a Curve25519 public and private DH keypair
    pk, sk = py25519.dh_keypair()
    """
    sk = create_string_buffer(lib25519_dh_SECRETKEYBYTES)
    pk = create_string_buffer(lib25519_dh_PUBLICKEYBYTES)
    lib.lib25519_dh_x25519_keypair(pk, sk)
    return pk.raw, sk.raw


def dh(pk, sk) -> bytes:
    if len(pk) != lib25519_dh_PUBLICKEYBYTES:
        raise ValueError
    if len(sk) != lib25519_dh_SECRETKEYBYTES:
        raise ValueError
    sk = create_string_buffer(sk)
    pk = create_string_buffer(pk)
    k = create_string_buffer(lib25519_dh_BYTES)
    lib.lib25519_dh_x25519(k, pk, sk)
    return k.raw


def sign_keypair():
    pk = create_string_buffer(lib25519_sign_PUBLICKEYBYTES)
    sk = create_string_buffer(lib25519_sign_SECRETKEYBYTES)
    lib.lib25519_sign_ed25519_keypair(pk, sk)
    return pk.raw, sk.raw


def sign(m, sk):
    assert len(sk) == lib25519_sign_SECRETKEYBYTES
    mlen = c_ulonglong(len(m))
    smlen = c_ulonglong(0)
    sm = create_string_buffer(len(m) + lib25519_sign_BYTES)
    m = create_string_buffer(m)
    sk = create_string_buffer(sk)
    lib.lib25519_sign_ed25519(sm, byref(smlen), m, mlen, sk)
    return sm.raw[:smlen.value]


def open(sm, pk):
    assert len(pk) == lib25519_sign_PUBLICKEYBYTES
    smlen = c_ulonglong(len(sm))
    m = create_string_buffer(len(sm))
    mlen = c_ulonglong(0)
    pk = create_string_buffer(pk)
    code = lib.lib25519_sign_ed25519_open(m, byref(mlen), sm, smlen, pk)
    __check(code)
    return m.raw[:mlen.value]

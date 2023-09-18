from unittest import TestCase, main

from py25519 import (
    dh,
    dh_keypair,
    lib25519_dh_BYTES,
    lib25519_dh_PUBLICKEYBYTES,
    lib25519_dh_SECRETKEYBYTES,
    lib25519_sign_BYTES,
    lib25519_sign_PUBLICKEYBYTES,
    lib25519_sign_SECRETKEYBYTES,
    open_sig,
    sign,
    sign_keypair,
)


class Test25519(TestCase):
    def setUp(self) -> None:
        pass

    def tearDown(self) -> None:
        pass

    def test_dh(self) -> None:
        """
        Tests that DH key exchange works
        """
        pk0, sk0 = dh_keypair()
        pk1, sk1 = dh_keypair()
        self.assertEqual(len(pk0), lib25519_dh_PUBLICKEYBYTES)
        self.assertEqual(len(sk0), lib25519_dh_SECRETKEYBYTES)
        self.assertEqual(dh(pk0, sk1), dh(pk1, sk0))
        self.assertEqual(len(dh(pk0, sk1)), lib25519_dh_BYTES)

    def test_sign_open(self) -> None:
        """
        Tests signing
        """
        pk, sk = sign_keypair()
        self.assertEqual(len(pk), lib25519_sign_PUBLICKEYBYTES)
        self.assertEqual(len(sk), lib25519_sign_SECRETKEYBYTES)
        msg = b"hello"
        signed_msg = sign(msg, sk)
        self.assertEqual(len(signed_msg), len(msg) + lib25519_sign_BYTES)
        self.assertEqual(msg, open_sig(signed_msg, pk))


if __name__ == "__main__":
    main()

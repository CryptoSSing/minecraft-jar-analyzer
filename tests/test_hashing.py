import hashlib

from analyzer.hashing import sha256_bytes, sha256_file


def test_sha256_known_vectors(tmp_path):
    # Official test vectors: SHA-256("") and SHA-256("abc").
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    assert sha256_file(empty) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert sha256_bytes(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_sha256_file_larger_than_chunk(tmp_path):
    data = b"x" * (3 * 1024 * 1024 + 17)  # spans several 1 MB chunks
    f = tmp_path / "big.bin"
    f.write_bytes(data)
    assert sha256_file(f) == hashlib.sha256(data).hexdigest()

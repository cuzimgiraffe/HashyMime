"""Kryptographische Hash-Berechnung fuer gaengige und historische Algorithmen."""

import hashlib
import struct

# MD2 Pure-Python Implementierung.
_MD2_S = [
    41,46,67,201,162,216,124,1,61,54,84,161,236,240,6,19,98,167,5,243,192,
    199,115,140,152,147,43,217,188,76,130,202,30,155,87,60,253,212,224,22,
    103,66,111,24,138,23,229,18,190,78,196,214,218,158,222,73,160,251,245,
    142,187,47,238,122,169,104,121,145,21,178,7,63,148,194,16,137,11,34,95,
    33,128,127,93,154,90,144,50,39,53,62,204,231,191,247,151,3,255,25,48,
    179,72,165,181,209,215,94,146,42,172,86,170,198,79,184,56,210,150,164,
    125,182,118,252,107,226,156,116,4,241,69,157,112,89,100,113,135,32,134,
    91,207,101,230,45,168,2,27,96,37,173,174,176,185,246,28,70,97,105,52,
    64,126,15,85,71,163,35,221,81,175,58,195,92,249,206,186,197,234,38,44,
    83,13,110,133,40,132,9,211,223,205,244,65,129,77,82,106,220,55,200,108,
    193,171,250,36,225,123,8,12,189,177,74,120,136,149,139,227,99,232,109,
    233,203,213,254,59,0,29,57,242,239,183,14,102,88,208,228,166,119,114,
    248,235,117,75,10,49,68,80,180,143,237,31,26,219,153,141,51,159,17,131,
    20
]

def _md2_hash(data: bytes) -> str:
    # Padding anhaengen.
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len] * pad_len)
    
    # Checksumme berechnen.
    checksum = [0] * 16
    L = 0
    for i in range(len(data) // 16):
        for j in range(16):
            c = data[i * 16 + j]
            checksum[j] ^= _MD2_S[c ^ L]
            L = checksum[j]
    data += bytes(checksum)
    
    # Message Digest Zustand aktualisieren.
    state = [0] * 48
    for i in range(len(data) // 16):
        for j in range(16):
            state[16 + j] = data[i * 16 + j]
            state[32 + j] = state[16 + j] ^ state[j]
        t = 0
        for j in range(18):
            for k in range(48):
                t = state[k] ^ _MD2_S[t]
                state[k] = t
            t = (t + j) % 256
    return bytes(state[:16]).hex()


# MD4 Pure-Python Implementierung.
def _md4_hash(data: bytes) -> str:
    def _left_rotate(n, b):
        return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

    def _f(x, y, z): return (x & y) | (~x & z)
    def _g(x, y, z): return (x & y) | (x & z) | (y & z)
    def _h(x, y, z): return x ^ y ^ z

    msg = bytearray(data)
    orig_len = len(data) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", orig_len)

    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    for i in range(0, len(msg), 64):
        X = list(struct.unpack("<16I", msg[i:i+64]))
        a, b, c, d = a0, b0, c0, d0

        # Erste Runde.
        for j in [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]:
            k = [3,7,11,19][j % 4]
            a = _left_rotate((a + _f(b,c,d) + X[j]) & 0xFFFFFFFF, k)
            a, b, c, d = d, a, b, c

        # Zweite Runde.
        for j in [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15]:
            k = [3,5,9,13][([0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15].index(j)) % 4]
            a = _left_rotate((a + _g(b,c,d) + X[j] + 0x5A827999) & 0xFFFFFFFF, k)
            a, b, c, d = d, a, b, c

        # Dritte Runde.
        for j in [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15]:
            k = [3,9,11,15][([0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15].index(j)) % 4]
            a = _left_rotate((a + _h(b,c,d) + X[j] + 0x6ED9EBA1) & 0xFFFFFFFF, k)
            a, b, c, d = d, a, b, c

        a0 = (a0 + a) & 0xFFFFFFFF
        b0 = (b0 + b) & 0xFFFFFFFF
        c0 = (c0 + c) & 0xFFFFFFFF
        d0 = (d0 + d) & 0xFFFFFFFF

    return struct.pack("<4I", a0, b0, c0, d0).hex()


# MD6 Rueckfallwert.
def _md6_hash(data: bytes) -> str:
    return "N/A (kein MD6-Paket verfuegbar)"


# SHA-0 Pure-Python Implementierung.
def _sha0_hash(data: bytes) -> str:
    def _sha0(msg: bytes) -> str:
        h0 = 0x67452301
        h1 = 0xEFCDAB89
        h2 = 0x98BADCFE
        h3 = 0x10325476
        h4 = 0xC3D2E1F0

        msg_len = len(msg) * 8
        msg += b'\x80'
        while len(msg) % 64 != 56:
            msg += b'\x00'
        msg += struct.pack('>Q', msg_len)

        for i in range(0, len(msg), 64):
            chunk = msg[i:i+64]
            w = list(struct.unpack('>16I', chunk))
            # Message Schedule ohne Bit-Rotation.
            for j in range(16, 80):
                w.append((w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16]) & 0xFFFFFFFF)

            a, b, c, d, e = h0, h1, h2, h3, h4
            for j in range(80):
                if j < 20:
                    f = (b & c) | ((~b) & d)
                    k = 0x5A827999
                elif j < 40:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif j < 60:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                else:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6
                tmp = (((a << 5) | (a >> 27)) & 0xFFFFFFFF) + f + e + k + w[j]
                tmp &= 0xFFFFFFFF
                e = d; d = c
                c = ((b << 30) | (b >> 2)) & 0xFFFFFFFF
                b = a; a = tmp

            h0 = (h0 + a) & 0xFFFFFFFF
            h1 = (h1 + b) & 0xFFFFFFFF
            h2 = (h2 + c) & 0xFFFFFFFF
            h3 = (h3 + d) & 0xFFFFFFFF
            h4 = (h4 + e) & 0xFFFFFFFF

        return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)

    return _sha0(data)


# Berechnet alle Hashes fuer eine Datei.
def compute_all(file_path: str) -> dict:
    with open(file_path, "rb") as f:
        data = f.read()

    results = {}

    # MD Familie
    results["MD2"] = _md2_hash(data)
    results["MD4"] = _md4_hash(data)
    results["MD5"] = hashlib.md5(data).hexdigest()
    results["MD6"] = _md6_hash(data)

    # SHA-0 und SHA-1
    results["SHA-0"] = _sha0_hash(data)
    results["SHA-1"] = hashlib.sha1(data).hexdigest()

    # SHA-2 Familie
    results["SHA-224"] = hashlib.sha224(data).hexdigest()
    results["SHA-256"] = hashlib.sha256(data).hexdigest()
    results["SHA-384"] = hashlib.sha384(data).hexdigest()
    results["SHA-512"] = hashlib.sha512(data).hexdigest()

    # SHA-3 Familie
    results["SHA3-224"] = hashlib.sha3_224(data).hexdigest()
    results["SHA3-256"] = hashlib.sha3_256(data).hexdigest()
    results["SHA3-384"] = hashlib.sha3_384(data).hexdigest()
    results["SHA3-512"] = hashlib.sha3_512(data).hexdigest()

    # BLAKE2 Familie
    results["BLAKE2b"] = hashlib.blake2b(data).hexdigest()
    results["BLAKE2s"] = hashlib.blake2s(data).hexdigest()

    return results

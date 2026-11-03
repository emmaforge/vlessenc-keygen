#!/usr/bin/env python3
"""生成 VLESS Encryption 密钥对（与 ./xray vlessenc 同一套格式）。

用法：
    python3 vlessenc-keygen.py [输出目录]

    输出目录缺省为 /etc/xboard-node/vlessenc（往 /etc 下写需要 root 权限）

    python3 vlessenc-keygen.py --verify <decryption> <encryption>

    验算面板里的一对 decryption / encryption 是不是同一对（本地验算，
    只输出匹不匹配和格式问题，绝不打印密钥内容）。

一次生成两对，来自 xray-core vlessenc 的原话：二选一使用，不要混用。
推荐用 ML-KEM-768 那对（抗量子）；X25519 那对也能用。

生成的文件（都在输出目录里）：
    mlkem768-decryption.txt -> 贴到面板「decryption」（服务端，含种子，勿外发）
    mlkem768-encryption.txt  -> 贴到面板「encryption」（客户端，公开密钥）
    x25519-decryption.txt    -> 贴到面板「decryption」（服务端，含私钥，勿外发）
    x25519-encryption.txt    -> 贴到面板「encryption」（客户端，公开密钥）

字符串格式（与 xray vlessenc 完全一致）：
    decryption = mlkem768x25519plus.native.600s.<服务端密钥>
    encryption = mlkem768x25519plus.native.0rtt.<客户端密钥>
    密钥部分是无填充 base64url；ML-KEM-768 的服务端密钥是 64 字节种子，
    客户端密钥是 1184 字节封装密钥。

依赖：仅 Python3 标准库，不用装任何包。ML-KEM-768 按 FIPS 203 实现，
X25519 按 RFC 7748 实现。私钥/种子只落在输出目录里，不会通过网络发往任何地方。

注意：VLESS Encryption 只是 xray 内核的功能，sing-box 不支持；
客户端也必须是 Xray-core 系的才认这两个字段。
"""

import base64
import hashlib
import os
import secrets
import sys

# ---------------------------------------------------------------- X25519
P25519 = 2 ** 255 - 19
A24 = 121665


def x25519(k_bytes: bytes, u_bytes: bytes) -> bytes:
    k = int.from_bytes(k_bytes, "little")
    k &= (1 << 254) - 8
    k |= 1 << 254
    x1 = int.from_bytes(u_bytes, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % P25519
        aa = a * a % P25519
        b = (x2 - z2) % P25519
        bb = b * b % P25519
        e = (aa - bb) % P25519
        c = (x3 + z3) % P25519
        d = (x3 - z3) % P25519
        da = d * a % P25519
        cb = c * b % P25519
        x3 = (da + cb) ** 2 % P25519
        z3 = x1 * (da - cb) ** 2 % P25519
        x2 = aa * bb % P25519
        z2 = e * (aa + A24 * e) % P25519
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, P25519 - 2, P25519) % P25519).to_bytes(32, "little")


# ---------------------------------------------------------------- ML-KEM-768
Q = 3329
N = 256
K = 3  # ML-KEM-768


def _bitrev7(i: int) -> int:
    r = 0
    for _ in range(7):
        r = (r << 1) | (i & 1)
        i >>= 1
    return r


def _ntt(f):
    f = [x % Q for x in f]
    i = 1
    length = 128
    while length >= 2:
        for start in range(0, N, 2 * length):
            zeta = pow(17, _bitrev7(i), Q)
            i += 1
            for j in range(start, start + length):
                t = zeta * f[j + length] % Q
                f[j + length] = (f[j] - t) % Q
                f[j] = (f[j] + t) % Q
        length //= 2
    return f


def _sample_ntt(rho: bytes, j: int, i: int):
    """FIPS 203 SampleNTT：SHAKE128(rho || j || i)，12 bit 拒绝采样。"""
    shake = hashlib.shake_128(rho + bytes([j, i]))
    out = []
    size = 1024
    buf = b""
    pos = 0
    while len(out) < N:
        if pos + 3 > len(buf):
            size *= 2
            buf = shake.digest(size)
        b0, b1, b2 = buf[pos], buf[pos + 1], buf[pos + 2]
        pos += 3
        d1 = b0 + 256 * (b1 % 16)
        d2 = (b1 // 16) + 16 * b2
        if d1 < Q:
            out.append(d1)
        if len(out) < N and d2 < Q:
            out.append(d2)
    return out


def _cbd(prf_bytes: bytes, eta: int):
    """中心二项分布，eta=2 时每系数取 4 bit（每字节内低位在前）。"""
    coeffs = []
    for i in range(N):
        x = 0
        y = 0
        for j in range(eta):
            p1 = 2 * eta * i + j
            x += (prf_bytes[p1 // 8] >> (p1 % 8)) & 1
            p2 = 2 * eta * i + eta + j
            y += (prf_bytes[p2 // 8] >> (p2 % 8)) & 1
        coeffs.append((x - y) % Q)
    return coeffs


def _gammas():
    # FIPS 203 Algorithm 11：分裂 NTT 的乘法需要 γ[i] = ζ^(2·BitRev7(i)+1)
    return [pow(17, 2 * _bitrev7(i) + 1, Q) for i in range(128)]


_GAMMAS = _gammas()


def _multiply_ntt(f, g):
    """FIPS 203 MultiplyNTTs：成对乘，不是按系数直接乘。"""
    h = [0] * N
    for i in range(128):
        a0, a1 = f[2 * i], f[2 * i + 1]
        b0, b1 = g[2 * i], g[2 * i + 1]
        h[2 * i] = (a0 * b0 + _GAMMAS[i] * a1 * b1) % Q
        h[2 * i + 1] = (a0 * b1 + a1 * b0) % Q
    return h


def _byte_encode_12(f) -> bytes:
    out = bytearray()
    for i in range(0, N, 2):
        a, b = f[i], f[i + 1]
        out.append(a & 0xFF)
        out.append(((a >> 8) & 0x0F) | ((b & 0x0F) << 4))
        out.append((b >> 4) & 0xFF)
    return bytes(out)


def mlkem768_encapsulation_key(seed64: bytes) -> bytes:
    """FIPS 203 ML-KEM.KeyGen_internal(d, z)，只返回 1184 字节封装密钥 ekPKE。"""
    d, _z = seed64[:32], seed64[32:]
    g = hashlib.sha3_512(d + bytes([K])).digest()
    rho, sigma = g[:32], g[32:]
    # A_hat[i][j] = SampleNTT(rho, j, i)
    a_hat = [[_sample_ntt(rho, j, i) for j in range(K)] for i in range(K)]
    nonce = 0
    s = []
    e = []
    for _ in range(K):
        s.append(_cbd(hashlib.shake_256(sigma + bytes([nonce])).digest(128), 2))
        nonce += 1
    for _ in range(K):
        e.append(_cbd(hashlib.shake_256(sigma + bytes([nonce])).digest(128), 2))
        nonce += 1
    s_hat = [_ntt(p) for p in s]
    e_hat = [_ntt(p) for p in e]
    t_hat = []
    for i in range(K):
        t = [0] * N
        for j in range(K):
            prod = _multiply_ntt(a_hat[i][j], s_hat[j])
            for c in range(N):
                t[c] = (t[c] + prod[c]) % Q
        for c in range(N):
            t[c] = (t[c] + e_hat[i][c]) % Q
        t_hat.append(t)
    return b"".join(_byte_encode_12(p) for p in t_hat) + rho


# ---------------------------------------------------------------- 验算
def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _parse_side(s: str, expect_ticket: str, role: str):
    """解析一侧字符串，返回 (密钥字节串, 问题列表)。绝不返回密钥原文以外的信息。"""
    s = s.strip()
    if s == "none":
        return None, [f"{role} 为 none（加密未启用）"]
    parts = s.split(".")
    if len(parts) < 4:
        return None, [f"{role} 格式不对：应为 mlkem768x25519plus.native.<票据>.<密钥>，实际只有 {len(parts)} 段"]
    method, mode, ticket, key_b64 = parts[0], parts[1], parts[2], parts[-1]
    problems = []
    if method != "mlkem768x25519plus":
        problems.append(f"{role} 方法不对：{method}（应为 mlkem768x25519plus）")
    if mode != "native":
        problems.append(f"{role} 模式不对：{mode}（应为 native）")
    if ticket != expect_ticket:
        problems.append(f"{role} 票据不对：{ticket}（{role} 侧应为 {expect_ticket}，两串可能贴反了）")
    try:
        key = _b64url_decode(key_b64)
    except Exception:
        return None, problems + [f"{role} 密钥部分不是合法的 base64url"]
    return key, problems


def verify_pair(dec_str: str, enc_str: str) -> int:
    """验算一对 decryption / encryption 是否匹配。只打印长度、类型和结论。"""
    dec_key, dec_problems = _parse_side(dec_str, "600s", "decryption")
    enc_key, enc_problems = _parse_side(enc_str, "0rtt", "encryption")
    for p in dec_problems + enc_problems:
        print("格式问题：" + p)
    if dec_key is None or enc_key is None:
        print("结论：无法验算（至少一侧解析失败或未启用）。")
        return 1
    print(f"decryption 密钥长度：{len(dec_key)} 字节")
    print(f"encryption 密钥长度：{len(enc_key)} 字节")
    if len(dec_key) == 64 and len(enc_key) == 1184:
        print("类型：ML-KEM-768 对")
        ok = mlkem768_encapsulation_key(dec_key) == enc_key
        print("结论：" + ("匹配：encryption 正是由 decryption 的种子派生出来的。"
                          if ok else "不匹配：encryption 不是由 decryption 的种子派生出来的，两串不是同一对。"))
        return 0 if ok else 1
    if len(dec_key) == 32 and len(enc_key) == 32:
        print("类型：X25519 对")
        ok = x25519(dec_key, (9).to_bytes(32, "little")) == enc_key
        print("结论：" + ("匹配：encryption 正是由 decryption 的私钥派生出来的。"
                          if ok else "不匹配：两串不是同一对。"))
        return 0 if ok else 1
    print("结论：不匹配：两串密钥类型对不上（混了两对的密钥）。")
    return 1


# ---------------------------------------------------------------- 主流程
def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _write(path: str, content: str, mode: int):
    with open(path, "w") as f:
        f.write(content + "\n")
    os.chmod(path, mode)


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--verify":
        if len(sys.argv) != 4:
            print("用法：python3 vlessenc-keygen.py --verify <decryption> <encryption>")
            print("  两串从面板原样复制，只在本机验算是否同一对，不打印密钥内容。")
            return 2
        return verify_pair(sys.argv[2], sys.argv[3])
    out_dir = sys.argv[1] if len(sys.argv) > 1 else "/etc/xboard-node/vlessenc"
    os.makedirs(out_dir, exist_ok=True)

    # --- X25519 对（与 genCurve25519 一致：钳制后的私钥才会被打印出来） ---
    priv = bytearray(secrets.token_bytes(32))
    priv[0] &= 248
    priv[31] &= 127
    priv[31] |= 64
    priv = bytes(priv)
    pub = x25519(priv, (9).to_bytes(32, "little"))
    dec_x = "mlkem768x25519plus.native.600s." + _b64url(priv)
    enc_x = "mlkem768x25519plus.native.0rtt." + _b64url(pub)

    # --- ML-KEM-768 对（种子 64 字节 = d || z，与 genMLKEM768 一致） ---
    seed = secrets.token_bytes(64)
    ek = mlkem768_encapsulation_key(seed)
    dec_pq = "mlkem768x25519plus.native.600s." + _b64url(seed)
    enc_pq = "mlkem768x25519plus.native.0rtt." + _b64url(ek)

    _write(os.path.join(out_dir, "x25519-decryption.txt"), dec_x, 0o600)
    _write(os.path.join(out_dir, "x25519-encryption.txt"), enc_x, 0o644)
    _write(os.path.join(out_dir, "mlkem768-decryption.txt"), dec_pq, 0o600)
    _write(os.path.join(out_dir, "mlkem768-encryption.txt"), enc_pq, 0o644)

    print("两对密钥已生成，二选一使用，不要混用。推荐 ML-KEM-768 那对（抗量子）。")
    print(f"目录：{out_dir}")
    print("  ML-KEM-768（推荐）：")
    print(f"    decryption -> {out_dir}/mlkem768-decryption.txt（服务端，含种子，勿外发）")
    print(f"    encryption -> {out_dir}/mlkem768-encryption.txt（客户端）")
    print("  X25519：")
    print(f"    decryption -> {out_dir}/x25519-decryption.txt（服务端，含私钥，勿外发）")
    print(f"    encryption -> {out_dir}/x25519-encryption.txt（客户端）")
    print("下一步：选定一对，把 decryption 贴到面板「decryption」，encryption 贴到"
          "面板「encryption」，保存后客户端更新订阅。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

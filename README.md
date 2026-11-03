# vlessenc-keygen

生成 VLESS Encryption 密钥对，输出格式和 `./xray vlessenc` 完全一致，
直接贴到 Xboard 面板的「decryption」和「encryption」两个字段就能用。

## 为什么需要这个脚本

面板里那两个字段的占位符写的是 `./xray vlessenc 生成`，但如果你用的是
Xboard-Node 这类把 xray-core 编进主程序的后端，服务器上并没有一个现成的
`xray` 可执行文件可以跑 `vlessenc`。这个脚本就是替代它的：只用 Python3
标准库，在服务器上直接生成，不用临时下载 xray 二进制，也不用把种子发给任何第三方。

## 特点

- 只需要 Python3 标准库，不用装任何包；
- ML-KEM-768 按 FIPS 203 实现，X25519 按 RFC 7748 实现，生成结果已用
  Go 标准库 `crypto/mlkem` / `crypto/ecdh` 交叉验证过，同一份种子算出的
  封装密钥和公钥一字不差；
- 私钥/种子只落在你指定的本地目录里，不经过任何第三方；
- decryption 文件权限自动设为 `0600`。

## 用法

下载脚本（单个文件）：

```bash
curl -LO https://raw.githubusercontent.com/emmaforge/vlessenc-keygen/main/vlessenc-keygen.py
```

生成：

```bash
python3 vlessenc-keygen.py
```

默认保存到 `/etc/xboard-node/vlessenc/`（往 `/etc` 下写需要 root 权限，
目录不存在会自动创建）。想换目录，第一个参数直接指定：

```bash
python3 vlessenc-keygen.py /root/vlessenc
```

## 生成的文件

一次生成两对，**二选一使用，不要混用**。推荐 ML-KEM-768 那对（抗量子）。

| 文件 | 用途 |
| --- | --- |
| `mlkem768-decryption.txt` | 贴到面板「decryption」，含 64 字节种子，勿外发 |
| `mlkem768-encryption.txt` | 贴到面板「encryption」，1184 字节封装密钥 |
| `x25519-decryption.txt` | 贴到面板「decryption」，含 X25519 私钥，勿外发 |
| `x25519-encryption.txt` | 贴到面板「encryption」，X25519 公钥 |

字符串格式（和 `xray vlessenc` 一样）：

```
decryption = mlkem768x25519plus.native.600s.<服务端密钥>
encryption = mlkem768x25519plus.native.0rtt.<客户端密钥>
```

密钥部分是无填充 base64url。

## 上线步骤

1. 选定一对（推荐 ML-KEM-768），把 decryption 贴到面板「decryption」，
   encryption 贴到面板「encryption」；
2. 面板保存后，客户端更新一次订阅，拿到新的加密配置再连接。

## 验算一对密钥是否匹配

如果你怀疑面板里的两串不是同一对（比如握手失败），可以在服务器本地验算，
不用把 decryption 发给任何人：

```bash
python3 vlessenc-keygen.py --verify "<decryption>" "<encryption>"
```

两串从面板原样复制进去。脚本只输出密钥长度、类型和匹不匹配的结论，
绝不打印密钥内容。decryption 含私钥种子，不要发到聊天记录或公开场合。

## 注意事项

- 两对不要混用：ML-KEM-768 的 decryption 只能配 ML-KEM-768 的 encryption，
  X25519 同理；
- decryption 文件里就是私钥/种子，不要公开、不要发给他人；
- VLESS Encryption 只是 xray 内核的功能，sing-box 不支持，客户端也必须是
  Xray-core 系的才认这两个字段。

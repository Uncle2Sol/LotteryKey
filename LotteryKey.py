import sys
import time
import re
import secrets
import hashlib
import requests 
from ecdsa import SigningKey, SECP256k1  

# Base58 (optimized)
b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58_encode(b):
    """Encode bytes to base58"""
    n = int.from_bytes(b, 'big')
    res = []
    while n > 0:
        n, r = divmod(n, 58)
        res.append(b58_digits[r])
    res = ''.join(res[::-1])
    pad = sum(1 for c in b if c == 0)  # Faster padding count
    return b58_digits[0] * pad + res

# Helpers
def sha256(data):
    return hashlib.sha256(data).hexdigest()

def get_uncompressed_pub(sk):
    vk = sk.verifying_key
    return b'\x04' + vk.to_string()

def generate_wif(priv_hex):
    version = b'\x80'
    priv_bytes = bytes.fromhex(priv_hex)
    payload = version + priv_bytes  # No compressed flag
    h1 = hashlib.sha256(payload).digest()
    h2 = hashlib.sha256(h1).digest()
    checksum = h2[:4]
    return base58_encode(payload + checksum)

def generate_address(pub_bytes):
    sha = hashlib.sha256(pub_bytes).digest()
    rip = hashlib.new('ripemd160', sha).digest()
    versioned = b'\x00' + rip
    h1 = hashlib.sha256(versioned).digest()
    h2 = hashlib.sha256(h1).digest()
    chk = h2[:4]
    return base58_encode(versioned + chk)

def derive_result(sk):
    priv_hex = sk.to_string().hex().zfill(64)
    pub_bytes = get_uncompressed_pub(sk)
    address = generate_address(pub_bytes)
    wif = generate_wif(priv_hex)
    return {'privHex': priv_hex, 'address': address, 'wif': wif}

def random_low_private_hex():
    # Optimized: single generate + check (low bias, fast)
    buf = secrets.token_bytes(32)
    buf = int.from_bytes(buf, 'big') % SECP256k1.order  # Bias low, but fast
    if buf == 0:
        return random_low_private_hex()  # Rare retry
    hex_str = format(buf, '064x')
    # Set low bits to random (simulate low priv)
    low_bits = secrets.randbits(208)  # 26 bytes * 8 = 208 bits
    hex_str = hex_str[:48] + format(low_bits, '052x')  # Prefix high, suffix low
    return hex_str

def generate_old_mode_keypair():
    if secrets.randbits(8) < 23:  # ~0.09 prob
        return SigningKey.generate(curve=SECP256k1)
    for _ in range(16):
        priv_hex = random_low_private_hex()
        secexp = int(priv_hex, 16)
        try:
            return SigningKey.from_secret_exponent(secexp, curve=SECP256k1)
        except:
            pass
    return SigningKey.generate(curve=SECP256k1)

def build_old_mode_result():
    keypair = generate_old_mode_keypair()
    legacy = derive_result(keypair)
    return {'privHex': legacy['privHex'], 'uncompressed': legacy}

def query_balance(addr):
    apis = [
        {'url': f'https://blockstream.info/api/address/{addr}', 'parse': lambda d: {'b': (d.get('chain_stats', {}).get('funded_txo_sum', 0) - d.get('chain_stats', {}).get('spent_txo_sum', 0)) / 1e8, 't': d.get('chain_stats', {}).get('tx_count', 0)}},
        {'url': f'https://blockchain.info/rawaddr/{addr}', 'parse': lambda d: {'b': d.get('final_balance', 0) / 1e8, 't': d.get('n_tx', 0)}}
    ]
    for api in apis:
        try:
            r = requests.get(api['url'], timeout=5)  # Shorter timeout
            if r.ok:
                data = r.json()
                res = api['parse'](data)
                return {'balance': res['b'], 'tx': res['t']}
        except:
            pass
    return {'balance': 0, 'tx': 0}

# Main
if __name__ == "__main__":
    print("比特币沉睡地址私钥碰撞生成器2025终极版 (优化版)")
    print("速度优化: ~1500+ keys/s (无API)")

    mode_input = input("选择模式: 1. 目标地址生成模式  2. 2009老鲸批量模拟模式\n输入 1 或 2: ").strip()
    if mode_input == '1':
        mode = 'prefix'
        prefix = input("前缀（支持正则，默认为 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa）: ").strip()
        if not prefix:
            prefix = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        suffix = input("后缀（支持正则）: ").strip()
        def check_match(addr):
            if prefix and not re.match(f'^{re.escape(prefix)}', addr):
                return False
            if suffix and not re.search(f'{re.escape(suffix)}$', addr):
                return False
            return True
        always_print = False
        print(f"使用前缀: {prefix}, 后缀: {suffix}")
    elif mode_input == '2':
        mode = 'old'
        always_print = True
        def check_match(addr):
            return True
        print("2009老鲸批量模拟模式")
    else:
        print("无效模式，退出。")
        sys.exit(1)

    query_balance_input = input("启用余额查询? (y/n, 默认 y): ").strip().lower()
    do_query = query_balance_input != 'n'

    alarm_addresses = {
        '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', '1FeexV6bAHb8ybZjqQMjJrcCrHGW9sb6uF', '1LdRcdxfbSnmCYYNdeYpUnztiYzVfBEQeC',
        '12ib7dApVFvg82TXKycWBNpN8kFyiAN1dr', '12tkqA9xSoowkzoERHMWNKsTey55YEBqkv', '1PeizMg76Cf96nUQrYg8xuoZWLQozU5zGW',
        '17Q7tuG2JwFFU9rXVj3uZqRtioH3mx2Jad', '1K6xGMUbs6ZTXBnhw1pippqwK6wjBWtNpL', '15ANYzzCp5BFHcCnVFzXqyibpzgPLWaD8b',
        '18ywPwj39nGjqBrQJSzZVq2izR12MDpDr8', '1HLoD9E4SDFFPDiYfNYnkBLQ85Y51J3Zb1', '198aMn6ZYAczwrE5NvNTUMyJ5qkfy4g3Hi',
        '1HLvaTs3zR3oev9ya7Pzp3GB9Gqfg6XYJT', '167ZWTT8n6s4ya8cGjqNNQjDwDGY31vmHg', '15Z5YJaaNSxeynvr6uW6jQZLwq3n1Hu6RX',
        '1FJuzzQFVMbiMGw6JtcXefdD64amy7mSCF', '1DzjE3ANaKLasY2n6e5ToJ4CQCXrvDvwsf', '1F34duy2eeMz5mSrvFepVzy7Y1rBsnAyWC',
        '1GR9qNz7zgtaW5HwwVpEJWMnGWhsbsieCG', '1AC4fMwgY8j9onSbXEWeH6Zan8QGMSdmtA', '1LruNZjwamWJXThX2Y8C2d47QqhAkkc5os'
    }

    start_time = time.time()
    attempts = 0
    last_speed_time = start_time
    print("状态: 生成中...")
    print("按 Ctrl+C 停止")
    print("-" * 50)

    try:
        while True:
            if mode == 'old':
                legacy = build_old_mode_result()
                priv_hex = legacy['privHex']
                address = legacy['uncompressed']['address']
                wif = legacy['uncompressed']['wif']
                is_old = True
            else:
                secexp = secrets.randbelow(SECP256k1.order)
                sk = SigningKey.from_secret_exponent(secexp, curve=SECP256k1)
                priv_hex = format(secexp, '064x')
                pub_bytes = get_uncompressed_pub(sk)
                address = generate_address(pub_bytes)
                wif = generate_wif(priv_hex)
                is_old = False

            # Alarm check (always query for alarms)
            if address in alarm_addresses:
                print("\n" + "="*50)
                print(f"🚨 警报！碰撞到知名沉睡地址: {address}")
                print(f"私钥 WIF: {wif}")
                print("生成已立即停止！请检查私钥安全！")
                print(f"地址: {address}")
                print(f"WIF: {wif}")
                res = query_balance(address)
                print(f"余额: {res['balance']:.8f} BTC")
                if res['balance'] > 0:
                    filename = f"RICH_{address[:10]}.txt"
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(f"暴富地址！\n地址: {address}\nWIF: {wif}\n余额: {res['balance']} BTC\n时间: {time.ctime()}")
                    print(f"已保存暴富信息到 {filename}")
                print("="*50)
                break

            attempts += 1
            do_print = always_print or (mode == 'prefix' and check_match(address))
            do_balance = do_query and (do_print or attempts % 100 == 0)  # Throttle queries

            if do_print:
                print(f"\n{'-'*30}")
                if is_old:
                    print("老鲸地址生成成功！")
                    print("使用未压缩公钥，模拟2009老式地址。")
                    print(f"老派地址(未压缩): {address}")
                    print(f"传统 WIF (5 开头): {wif}")
                    print("提示：若钱包导入后显示不同地址，请确认使用了对应的 WIF。")
                else:
                    print("Vanity 地址生成成功！")
                    print(f"地址: {address}")
                    print(f"WIF: {wif}")
                print(f"{'-'*30}")

            if do_balance:
                res = query_balance(address)
                balance_str = f"{res['balance']:.8f} BTC"
                if res['balance'] > 0:
                    print(f"暴富了！余额 {balance_str}！")
                    filename = f"RICH_{address[:10]}.txt"
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(f"暴富地址！\n地址: {address}\nWIF: {wif}\n余额: {res['balance']} BTC\n时间: {time.ctime()}")
                    print(f"已保存到 {filename}")
                else:
                    print(f"余额 {balance_str}")

            # Real-time stats (no newline)
            now = time.time()
            if now - last_speed_time >= 1:
                elapsed = now - start_time
                speed = attempts / elapsed
                sys.stdout.write(f"\r已尝试: {attempts:,} 次 | 运行: {elapsed:.1f}s | 速度: {speed:.0f} keys/s")
                sys.stdout.flush()
                last_speed_time = now

            # No sleep: full speed!

    except KeyboardInterrupt:
        elapsed = time.time() - start_time
        speed = attempts / elapsed if elapsed > 0 else 0
        print(f"\n\n已停止。总尝试: {attempts:,} 次, 运行: {elapsed:.1f}s, 平均速度: {speed:.0f} keys/s")
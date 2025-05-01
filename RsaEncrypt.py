"""
RSA加密Python实现
使用RSA公钥加密数据，采用OAEP填充方案
兼容Java实现的加密方式
"""
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import base64
import os
# 导入哈希和签名模块
from Crypto.Hash import SHA256,SHA1
from Crypto.Signature import pss

def rsa_encrypt(plaintext, public_key_path):
    """
    使用RSA公钥加密数据，采用OAEPWithSHA-256AndMGF1Padding填充方案
    :param plaintext: 要加密的明文
    :param public_key_path: PEM格式的公钥文件路径
    :return: Base64编码的加密结果
    """
    # 1. 读取PEM格式的公钥文件
    with open(public_key_path, 'r') as f:
        public_key_pem = f.read()
    
    # 2. 加载公钥
    public_key = RSA.import_key(public_key_pem)
    
    # 3. 创建加密器，使用SHA-256哈希和MGF1填充
    # 注释掉的是简化版本
    # cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)

    # 加密时应显式指定MGF1的哈希算法，确保与Java实现兼容
    cipher = PKCS1_OAEP.new(
        public_key, 
        hashAlgo=SHA256, 
        mgfunc=lambda x,y: PKCS1_OAEP.MGF1(x,y,SHA1)
    )
    
    # 4. 加密数据
    encrypted_bytes = cipher.encrypt(plaintext.encode('utf-8'))
    
    # 5. 打印验证信息
    print(f"原始字节长度: {len(encrypted_bytes)}")
    print(f"原始字节内容: {encrypted_bytes}")
    base64_str = base64.b64encode(encrypted_bytes).decode('utf-8')
    print(f"Base64编码后长度: {len(base64_str)}")
    
    # 6. 验证Base64解码
    decoded_bytes = base64.b64decode(base64_str)
    print(f"解码后字节长度: {len(decoded_bytes)}")
    print(f"解码后字节内容: {decoded_bytes}")
    print(f"解码验证结果: {encrypted_bytes == decoded_bytes}")
    
    # 7. 返回Base64编码结果
    return base64_str


if __name__ == '__main__':
    # 示例用法
    public_key_path = os.path.join(os.path.dirname(__file__), 'src/public_key.pem')
    plaintext = "python 加密"
    encrypted = rsa_encrypt(plaintext, public_key_path)
    print(f"加密后密文:\n{encrypted}")
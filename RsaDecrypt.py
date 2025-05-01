"""
RSA解密Python实现
使用RSA私钥解密数据，采用OAEP填充方案
兼容Java实现的解密方式
"""
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256,SHA1
import base64
import os
import sys

def rsa_decrypt(ciphertext, private_key_path):
    """
    使用RSA私钥解密数据，采用OAEPWithSHA-256AndMGF1Padding填充方案
    :param ciphertext: Base64编码的密文
    :param private_key_path: PEM格式的私钥文件路径
    :return: 解密后的明文
    """
    try:
        # 1. 读取PEM格式的私钥文件
        with open(private_key_path, 'r') as f:
            private_key_pem = f.read()
        
        print(f"私钥文件路径: {private_key_path}")
        print(f"私钥前20个字符: {private_key_pem[:20]}...")
        
        # 2. 加载私钥
        private_key = RSA.import_key(private_key_pem)
        print(f"私钥大小: {private_key.size_in_bits()} 位")
        
        # 3. 创建解密器，使用SHA-256哈希和MGF1填充
        # 确保与Java实现使用相同的参数
        cipher = PKCS1_OAEP.new(
            private_key, 
            hashAlgo=SHA256, 
            mgfunc=lambda x,y: PKCS1_OAEP.MGF1(x,y,SHA1)
        )
        
        # 4. Base64解码并解密数据
        print(f"密文长度: {len(ciphertext)}")
        encrypted_bytes = base64.b64decode(ciphertext)
        print(f"解码后字节长度: {len(encrypted_bytes)}")
        
        # 5. 尝试解密
        decrypted_bytes = cipher.decrypt(encrypted_bytes)
        
        # 6. 返回UTF-8解码的明文
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        # 7. 异常处理
        print(f"解密过程中出错: {str(e)}")
        print(f"错误类型: {type(e).__name__}")
        return None

if __name__ == '__main__':
    # 检查私钥文件是否存在
    private_key_path = os.path.join(os.path.dirname(__file__), 'src/private_key.pem')
    if not os.path.exists(private_key_path):
        print(f"错误: 私钥文件不存在: {private_key_path}")
        sys.exit(1)
        
    # 使用预定义的密文进行解密测试
    python_ciphertext = "IYtoBECNzowOO8JQ6xIhWM6SGtbgwhmDkOo4nUxb2NueLU5c5xfyCyLmY5X/TMeWwyd+PCrcnzME1oYoeP84Daw7kWEgS6OL/aMM2aXJRz6M4ky3Hq2e7Ci1Ccfw7zURBPqgasNeflySmWV+w1mCPvjsx3bgm21Xg7vvEJQbh4hZV1Ql60ieXyzWyaDs5GprTIz34Z8VlFCDPxfDquIuyCxzd2NDkDq59qkbu8z+Mb3kjNgDyvytlZW7ICIaxEz/4T+I2sMufN/Te0TbWJfXDAFnYUR5RQaoDBRjzlkKMxs06CvD/t5QoUibmYC+AnO9BV68bye8gCNHX6nPIIRlxQ=="
    
    # 尝试使用Python脚本中的密文解密
    print("\n=== 尝试使用Python脚本中的密文解密 ===")
    python_decrypted = rsa_decrypt(python_ciphertext, private_key_path)
    if python_decrypted:
        print(f"解密后明文:\n{python_decrypted}")
    

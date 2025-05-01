/**
 * RSA密钥对生成器
 * 用于生成RSA公钥和私钥，并将它们保存为PEM格式的文件
 * 支持自定义密钥长度，默认使用2048位
 */
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class RsaKeyGenerator {
    
    /**
     * 主方法：生成RSA密钥对并保存到指定文件
     * @param args 命令行参数（未使用）
     * @throws NoSuchAlgorithmException 如果RSA算法不可用
     * @throws IOException 如果文件操作出错
     */
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        generateAndSaveRsaKeyPair("private_key.pem", "public_key.pem", 2048);
    }
    
    /**
     * 生成RSA密钥对并保存为PEM格式文件
     * @param privateKeyPath 私钥保存路径
     * @param publicKeyPath 公钥保存路径
     * @param keySize 密钥长度（位数）
     * @throws NoSuchAlgorithmException 如果RSA算法不可用
     * @throws IOException 如果文件操作出错
     */
    public static void generateAndSaveRsaKeyPair(String privateKeyPath, String publicKeyPath, int keySize) 
            throws NoSuchAlgorithmException, IOException {
        // 1. 生成RSA密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        
        // 2. 将私钥转换为PEM格式并保存
        String privateKeyPEM = "-----BEGIN PRIVATE KEY-----\n" +
                Base64.getMimeEncoder().encodeToString(privateKey.getEncoded()) +
                "\n-----END PRIVATE KEY-----";
        
        try (FileOutputStream fos = new FileOutputStream(privateKeyPath)) {
            fos.write(privateKeyPEM.getBytes());
        }
        
        // 3. 将公钥转换为PEM格式并保存
        String publicKeyPEM = "-----BEGIN PUBLIC KEY-----\n" +
                Base64.getMimeEncoder().encodeToString(publicKey.getEncoded()) +
                "\n-----END PUBLIC KEY-----";
        
        try (FileOutputStream fos = new FileOutputStream(publicKeyPath)) {
            fos.write(publicKeyPEM.getBytes());
        }
        
        System.out.println("RSA密钥对已生成并保存到:");
        System.out.println("私钥: " + privateKeyPath);
        System.out.println("公钥: " + publicKeyPath);
    }
}
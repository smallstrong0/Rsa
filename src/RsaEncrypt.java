/**
 * RSA加密实现类
 * 使用RSA公钥加密数据，采用OAEP填充方案
 * 支持从资源文件读取公钥
 */
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource.PSpecified;

import java.util.Arrays;
import java.util.Base64;

public class RsaEncrypt  {

    /**
     * 主方法：演示RSA加密过程
     * @param args 命令行参数（未使用）
     * @throws Exception 如果加密过程中出错
     */
    public static void main(String[] args) throws Exception {
        // 1. 从类路径加载公钥文件
        String publicKeyPEM = readPublicKeyFromResources();
        
        // 2. 清理PEM格式中的头尾和空格
        publicKeyPEM = publicKeyPEM
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");

        // 3. 将PEM格式的公钥转换为PublicKey对象
        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        // 4. 初始化加密器（与解密端保持相同参数）
        // 注释掉的是另一种初始化方式
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // 使用OAEPParameterSpec显式指定参数
        // Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        // OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSpecified.DEFAULT);
        // cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParams);

        // 5. 定义要加密的明文
        String plaintext = "java 加密";
        
        // 6. 加密明文（自动处理填充）
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        
        // 7. 转换为Base64字符串并输出验证信息
        System.out.println("原始字节长度: " + encryptedBytes.length);
        System.out.println("原始字节内容: " + Arrays.toString(encryptedBytes));
        String base64Str = Base64.getEncoder().encodeToString(encryptedBytes);
        System.out.println("Base64编码后长度: " + base64Str.length());
        System.out.println("加密后密文:\n" + base64Str);
        
        // 8. 验证Base64解码是否正确
        byte[] decodedBytes = Base64.getDecoder().decode(base64Str);
        System.out.println("解码后字节长度: " + decodedBytes.length);
        System.out.println("解码后字节内容: " + Arrays.toString(decodedBytes));
        System.out.println("解码验证结果: " + Arrays.equals(encryptedBytes, decodedBytes));
    }

    /**
     * 从类路径资源读取公钥文件
     * @return 公钥文件内容字符串
     * @throws IOException 如果读取文件出错
     */
    public static String readPublicKeyFromResources() throws IOException {
        try (InputStream inputStream = RsaEncrypt.class.getResourceAsStream("./public_key.pem")) {
            if (inputStream == null) {
                throw new RuntimeException("公钥文件未找到");
            }
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] data = new byte[16384];
            int nRead;
            while ((nRead = inputStream.read(data, 0, data.length)) != -1) {
                buffer.write(data, 0, nRead);
            }
            buffer.flush();
            return new String(buffer.toByteArray(), StandardCharsets.UTF_8);
        }
    }
}
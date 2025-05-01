/**
 * RSA解密实现类
 * 使用RSA私钥解密数据，采用OAEP填充方案
 * 支持从资源文件读取私钥
 */
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource.PSpecified;

import java.util.Arrays;
import java.util.Base64;


/**
 * @Description RSA解密实现
 * @Author roson
 * @Date 2025/4/8 15:06
 */

public class RsaDecrypt{
    /**
     * 主方法：演示RSA解密过程
     * @param args 命令行参数（未使用）
     * @throws Exception 如果解密过程中出错
     */
    public static void main(String[] args) throws Exception {
        // 1. 从类路径加载私钥文件（路径为资源目录下的 private_key.pem）
        String privateKeyPEM = readPrivateKeyFromResources();

        // 2. 清理 PEM 格式中的头尾和空格
        privateKeyPEM = privateKeyPEM
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        // 3. 将 PEM 格式的私钥转换为 PrivateKey 对象
        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        // 4. 待解密的Base64编码密文
        String encryptedBase64 = "IYtoBECNzowOO8JQ6xIhWM6SGtbgwhmDkOo4nUxb2NueLU5c5xfyCyLmY5X/TMeWwyd+PCrcnzME1oYoeP84Daw7kWEgS6OL/aMM2aXJRz6M4ky3Hq2e7Ci1Ccfw7zURBPqgasNeflySmWV+w1mCPvjsx3bgm21Xg7vvEJQbh4hZV1Ql60ieXyzWyaDs5GprTIz34Z8VlFCDPxfDquIuyCxzd2NDkDq59qkbu8z+Mb3kjNgDyvytlZW7ICIaxEz/4T+I2sMufN/Te0TbWJfXDAFnYUR5RQaoDBRjzlkKMxs06CvD/t5QoUibmYC+AnO9BV68bye8gCNHX6nPIIRlxQ==";
        // String encryptedBase64 = "cIZKzEHq6NAWfuN4aSVv0SZEi+fFQoMCWp33j21YDYfiiK7FRD/SDC6sF+r8WQ3UW70rdfWb0SJuFVKv+Wo4xCoCSML9qcAzkYW+lqPA1K9deA5yJLUeyalSbSCUEjpWnfG+pUT0gdCZKhPCus83v8XOcbg10fi4R9b0SOVVeIipWEPr8NKwMSNX9WDLFuiu/bYpjD+QWoHegwDrQxrB6SQ9nij81bR3HCiUyvqTul/oINWlpAo9IQLU1CM9xkFQv5id5HgKiDwR34EniF9u9/I1U2IOA9+84T5vc8Iehnl/KaWqpxkwfRkOTqvy27CgVYMNr/gt6zmnJKlMAQxCfw==";
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedBase64);
        
        // 5. 初始化解密器（注释掉的是另一种初始化方式）
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        System.out.println("Base64编码长度: " + encryptedBase64.length());
        System.out.println("解码后字节长度: " + encryptedBytes.length);
        System.out.println("解码后字节内容: " + Arrays.toString(encryptedBytes));
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        // 6. 使用OAEPParameterSpec显式指定参数进行解密
        // Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        // OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSpecified.DEFAULT);
        // cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);
        // byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
 
        // 7. 转换为字符串并输出
        System.out.println("解密后原文:\n" + new String(decryptedBytes, "UTF-8"));
         
        // 8. 验证Base64编码是否正确
        String reEncoded = Base64.getEncoder().encodeToString(encryptedBytes);
        System.out.println("重新编码后Base64: " + reEncoded);
        System.out.println("编码验证结果: " + encryptedBase64.equals(reEncoded));
    }

    /**
     * 从类路径资源读取私钥文件
     * @return 私钥文件内容字符串
     * @throws IOException 如果读取文件出错
     */
    public static String readPrivateKeyFromResources() throws IOException {
        // 从类路径读取资源文件（路径以 / 开头表示根目录）
        try (InputStream inputStream = RsaDecrypt.class.getResourceAsStream("./private_key.pem")) {
            if (inputStream == null) {
                throw new RuntimeException("私钥文件未找到");
            }
            // 读取输入流内容为字符串
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            int nRead;
            byte[] data = new byte[16384];
            while ((nRead = inputStream.read(data, 0, data.length)) != -1) {
                buffer.write(data, 0, nRead);
            }
            buffer.flush();
            return new String(buffer.toByteArray(), StandardCharsets.UTF_8);
        }
    }
}



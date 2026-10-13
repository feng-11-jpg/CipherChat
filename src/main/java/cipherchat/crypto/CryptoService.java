package cipherchat.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Properties;

/**
 * 端到端加密工具类。整个项目的密码学逻辑都集中在这里,服务器不参与任何加解密。
 *
 * <p>方案:</p>
 * <ol>
 *   <li>每个用户在本机生成一对 X25519 长期密钥,私钥只留在本机(见
 *       {@link #loadOrCreateKeyPair(String)}),公钥交给服务器转发给联系人;</li>
 *   <li>发送时用自己的私钥 + 对方公钥做 ECDH 协商,得到共享密钥;</li>
 *   <li>共享密钥经 SHA-256 派生出 256 位 AES 密钥(见 {@link #deriveKey});</li>
 *   <li>用 AES-256-GCM 加密正文,GCM 自带完整性认证,密文被改动会解密失败。</li>
 * </ol>
 *
 * <p>因此服务器只能看到密文和元数据(谁发给谁、时间、密文长度),拿不到正文。</p>
 */
public final class CryptoService {
    private static final SecureRandom RANDOM = new SecureRandom();
    /** 派生密钥时混入的固定上下文串,避免把共享密钥直接当 AES 密钥用 */
    private static final String KEY_CONTEXT = "CipherChat-v1";

    /** 工具类不允许实例化 */
    private CryptoService() {
    }

    /** 一条已加密的消息:GCM 初始向量 + 密文(含认证标签)。 */
    public record EncryptedMessage(byte[] iv, byte[] ciphertext) {
    }

    /**
     * 读取本机保存的长期身份密钥,不存在就新建一对并写盘。
     *
     * <p>存放位置:{@code %USERPROFILE%/.cipherchat/keys/<用户名>.properties},
     * 内容是 Base64 编码的 PKCS#8 私钥和 X.509 公钥。</p>
     *
     * <p>注意:这个文件就是你的身份。删掉或用另一台设备登录同名账号会生成新密钥,
     * 此前收到的离线密文将再也无法解密(客户端会提示"无法解密此消息")。</p>
     */
    public static KeyPair loadOrCreateKeyPair(String username) throws GeneralSecurityException, IOException {
        Path keyDir = Path.of(System.getProperty("user.home"), ".cipherchat", "keys");
        Files.createDirectories(keyDir);
        Path keyFile = keyDir.resolve(safeName(username) + ".properties");
        KeyFactory factory = KeyFactory.getInstance("X25519");

        if (Files.exists(keyFile)) {
            Properties properties = new Properties();
            try (var reader = Files.newBufferedReader(keyFile, StandardCharsets.UTF_8)) {
                properties.load(reader);
            }
            byte[] privateBytes = Base64.getDecoder().decode(properties.getProperty("private"));
            byte[] publicBytes = Base64.getDecoder().decode(properties.getProperty("public"));
            PrivateKey privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(privateBytes));
            PublicKey publicKey = factory.generatePublic(new X509EncodedKeySpec(publicBytes));
            return new KeyPair(publicKey, privateKey);
        }

        KeyPairGenerator generator = KeyPairGenerator.getInstance("X25519");
        KeyPair keyPair = generator.generateKeyPair();
        Properties properties = new Properties();
        properties.setProperty("private", Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
        properties.setProperty("public", Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        try (var writer = Files.newBufferedWriter(keyFile, StandardCharsets.UTF_8)) {
            properties.store(writer, "CipherChat local X25519 identity key");
        }
        return keyPair;
    }

    /** 把裸字节形式的公钥还原成 {@link PublicKey},用于对方发来的公钥。 */
    public static PublicKey decodePublicKey(byte[] encoded) throws GeneralSecurityException {
        return KeyFactory.getInstance("X25519").generatePublic(new X509EncodedKeySpec(encoded));
    }

    /**
     * 加密一段文本。
     *
     * @param plaintext     待加密的明文
     * @param ownPrivateKey 自己的私钥
     * @param peerPublicKey 对方公钥
     * @param from 发送方用户名,参与密钥派生和 AAD
     * @param to   接收方用户名,参与密钥派生和 AAD
     * @return IV 与密文。IV 每次随机生成,绝不复用
     */
    public static EncryptedMessage encrypt(String plaintext, PrivateKey ownPrivateKey,
                                           PublicKey peerPublicKey, String from, String to)
            throws GeneralSecurityException {
        SecretKeySpec key = deriveKey(ownPrivateKey, peerPublicKey, from, to);
        byte[] iv = new byte[12];
        RANDOM.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        cipher.updateAAD(aad(from, to));
        return new EncryptedMessage(iv, cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * 解密一段密文。参数必须与加密方完全一致(同一对密钥、同样的 from/to),
     * 否则 GCM 认证会失败并抛异常,而不是返回乱码。
     */
    public static String decrypt(byte[] iv, byte[] ciphertext, PrivateKey ownPrivateKey,
                                 PublicKey peerPublicKey, String from, String to)
            throws GeneralSecurityException {
        SecretKeySpec key = deriveKey(ownPrivateKey, peerPublicKey, from, to);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        cipher.updateAAD(aad(from, to));
        return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
    }

    /**
     * 用 X25519 协商出共享密钥,再用 SHA-256 派生出 AES-256 密钥。
     *
     * <p>关键细节:派生时把两个用户名按字典序拼接后参与哈希。双方各自计算的
     * 顺序可能相反,排序能保证两个人算出同一个密钥;同时把用户名绑进密钥,
     * 使得密钥只对这一对用户有效。</p>
     */
    private static SecretKeySpec deriveKey(PrivateKey ownPrivateKey, PublicKey peerPublicKey,
                                           String firstUser, String secondUser)
            throws GeneralSecurityException {
        KeyAgreement agreement = KeyAgreement.getInstance("X25519");
        agreement.init(ownPrivateKey);
        agreement.doPhase(peerPublicKey, true);
        byte[] sharedSecret = agreement.generateSecret();

        String users = firstUser.compareTo(secondUser) <= 0
                ? firstUser + "|" + secondUser
                : secondUser + "|" + firstUser;
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(KEY_CONTEXT.getBytes(StandardCharsets.UTF_8));
        digest.update((byte) 0);
        digest.update(users.getBytes(StandardCharsets.UTF_8));
        digest.update((byte) 0);
        byte[] keyBytes = digest.digest(sharedSecret);
        return new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * 附加认证数据(AAD):把收发双方写进 GCM 的认证范围。
     * 这样即使有人篡改了包头里的收发人,解密也会失败。
     */
    private static byte[] aad(String from, String to) {
        return (from + "\0" + to).getBytes(StandardCharsets.UTF_8);
    }

    /** 把用户名里不适合做文件名的字符替换掉,防止路径穿越。 */
    private static String safeName(String username) {
        return username.replaceAll("[^a-zA-Z0-9_\\-\\u4e00-\\u9fa5]", "_");
    }
}

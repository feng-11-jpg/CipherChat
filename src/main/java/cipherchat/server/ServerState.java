package cipherchat.server;

import cipherchat.common.Packet;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serial;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.HashSet;
import java.util.Set;

/**
 * 服务器端全部需要长期保存的状态,整体作为一个对象序列化到磁盘。
 *
 * <p>包含四张表:账号、离线消息、联系人关系、待处理的联系人申请。
 * 所有对外方法都加了 {@code synchronized}:每个客户端连接由一个虚拟线程处理,
 * 多个线程会并发读写这些 Map,必须整体互斥,否则会出现"边写边序列化"的脏状态。</p>
 *
 * <p>每次状态变化(注册、登录更新公钥、加好友、消息进出队)都会立刻调用
 * {@link #save()} 落盘,所以服务器重启后数据仍在。</p>
 */
final class ServerState implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;
    /** PBKDF2 迭代次数。轮数越高越难暴力破解,同时登录耗时也越长 */
    private static final int ITERATIONS = 120_000;
    private static final SecureRandom RANDOM = new SecureRandom();

    /** 用户名 -> 账号(密码盐、密码哈希、公钥)。密码本身不保存 */
    private Map<String, Account> accounts = new HashMap<>();
    /** 用户名 -> 尚未投递的离线消息密文。对方登录后被取走并删除 */
    private Map<String, List<Packet>> offlineMessages = new HashMap<>();
    /** 用户名 -> 其联系人集合。加好友成功后双向写入,保证两边都看得到 */
    private Map<String, Set<String>> contacts = new HashMap<>();
    /** 用户名 -> 别人向他发起的、尚未处理的联系人申请 */
    private Map<String, Set<String>> pendingContactRequests = new HashMap<>();
    /** 对应的状态文件路径。transient:它是"存到哪"的信息,不需要被序列化进去 */
    private transient Path stateFile;

    /**
     * 从磁盘加载状态;文件不存在或读坏了就返回一份全新的空状态。
     *
     * <p>读坏时不抛异常而是重建,是刻意的取舍:序列化格式一旦不兼容,
     * 服务器仍要能启动,只是数据回到初始状态(并打印一行错误提示)。</p>
     */
    static ServerState load(Path stateFile) {
        if (Files.exists(stateFile)) {
            try (ObjectInputStream input = new ObjectInputStream(Files.newInputStream(stateFile))) {
                ServerState state = (ServerState) input.readObject();
                state.stateFile = stateFile;
                state.normalize();
                return state;
            } catch (IOException | ClassNotFoundException e) {
                System.err.println("无法读取旧状态，将创建新状态: " + e.getMessage());
            }
        }
        ServerState state = new ServerState();
        state.stateFile = stateFile;
        return state;
    }

    /**
     * 注册新账号。用户名已存在返回 false。
     * 密码不存明文,而是随机盐 + PBKDF2 哈希。
     */
    synchronized boolean register(String username, String password, byte[] publicKey)
            throws GeneralSecurityException, IOException {
        if (accounts.containsKey(username)) {
            return false;
        }
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        accounts.put(username, new Account(salt, passwordHash(password, salt), publicKey.clone()));
        contacts.put(username, new HashSet<>());
        pendingContactRequests.put(username, new HashSet<>());
        save();
        return true;
    }

    /**
     * 校验登录。密码用 {@link MessageDigest#isEqual} 做等长比较,避免计时侧信道。
     * 校验通过后用本次登录的公钥覆盖旧公钥——这样换台电脑登录同名账号也能继续通信。
     */
    synchronized boolean authenticate(String username, String password, byte[] publicKey)
            throws GeneralSecurityException, IOException {
        Account account = accounts.get(username);
        if (account == null || !MessageDigest.isEqual(account.passwordHash, passwordHash(password, account.salt))) {
            return false;
        }
        account.publicKey = publicKey.clone();
        save();
        return true;
    }

    /** 判断用户名是否已注册。加好友前用来区分"找不到用户"和"申请成功" */
    synchronized boolean hasUser(String username) {
        return accounts.containsKey(username);
    }

    /** 取某人的联系人及其公钥。只返回已成为联系人的人,不泄露其他账号信息 */
    synchronized Map<String, byte[]> contactPublicKeys(String username) {
        Map<String, byte[]> copy = new HashMap<>();
        for (String contact : contacts.getOrDefault(username, Set.of())) {
            Account account = accounts.get(contact);
            if (account != null) {
                copy.put(contact, account.publicKey.clone());
            }
        }
        return copy;
    }

    /** 判断两人是否为联系人。发消息前的权限校验依赖它 */
    synchronized boolean areContacts(String first, String second) {
        return contacts.getOrDefault(first, Set.of()).contains(second);
    }

    /** 记录一条好友申请。重复申请、加自己、已是好友等情况用枚举区分,便于给出准确提示 */
    synchronized ContactRequestResult addContactRequest(String from, String to) throws IOException {
        if (!accounts.containsKey(to)) {
            return ContactRequestResult.USER_NOT_FOUND;
        }
        if (from.equals(to)) {
            return ContactRequestResult.SELF;
        }
        if (areContacts(from, to)) {
            return ContactRequestResult.ALREADY_CONTACTS;
        }
        Set<String> pending = pendingContactRequests.computeIfAbsent(to, ignored -> new HashSet<>());
        if (!pending.add(from)) {
            return ContactRequestResult.ALREADY_PENDING;
        }
        save();
        return ContactRequestResult.CREATED;
    }

    /**
     * 处理好友申请的应答。只有申请确实存在才生效,防止有人伪造一个应答来单向建立关系。
     * 同意时双向写入 contacts,让双方列表同时更新。
     */
    synchronized boolean respondToContactRequest(String receiver, String requester, boolean accepted)
            throws IOException {
        Set<String> pending = pendingContactRequests.computeIfAbsent(receiver, ignored -> new HashSet<>());
        if (!pending.remove(requester)) {
            return false;
        }
        if (accepted) {
            contacts.computeIfAbsent(receiver, ignored -> new HashSet<>()).add(requester);
            contacts.computeIfAbsent(requester, ignored -> new HashSet<>()).add(receiver);
        }
        save();
        return true;
    }

    /** 待处理的好友申请列表。对方登录时用来补发申请弹窗 */
    synchronized Set<String> pendingRequests(String username) {
        return Set.copyOf(pendingContactRequests.getOrDefault(username, Set.of()));
    }

    /** 对方不在线时,把这条密文消息存起来等他上线。存的是密文,服务器解不开 */
    synchronized void queueMessage(Packet packet) throws IOException {
        offlineMessages.computeIfAbsent(packet.to, key -> new ArrayList<>()).add(packet);
        save();
    }

    /**
     * 取走某人的全部离线消息,并删除已取走的部分,保证不重复投递。
     * 注意:取走后本机若无当时的私钥就再也解不开了。
     */
    synchronized List<Packet> takeOfflineMessages(String username) throws IOException {
        List<Packet> messages = offlineMessages.remove(username);
        if (messages == null) {
            return List.of();
        }
        save();
        return List.copyOf(messages);
    }

    /**
     * PBKDF2-HMAC-SHA256 口令哈希。同一密码每次注册因盐不同而得到不同结果,
     * 让攻击者无法用彩虹表批量还原。
     */
    private static byte[] passwordHash(String password, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, 256);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    /**
     * 兜底修复:反序列化出来的对象可能因为版本差异出现 null 字段,这里统一补齐,
     * 并保证每个账号在 contacts / pendingContactRequests 里都有对应条目。
     */
    private void normalize() {
        if (accounts == null) accounts = new HashMap<>();
        if (offlineMessages == null) offlineMessages = new HashMap<>();
        if (contacts == null) contacts = new HashMap<>();
        if (pendingContactRequests == null) pendingContactRequests = new HashMap<>();
        for (String username : accounts.keySet()) {
            contacts.computeIfAbsent(username, ignored -> new HashSet<>());
            pendingContactRequests.computeIfAbsent(username, ignored -> new HashSet<>());
        }
    }

    /** 好友申请的处理结果,对应界面上几种不同的提示文案 */
    enum ContactRequestResult {
        CREATED, USER_NOT_FOUND, SELF, ALREADY_CONTACTS, ALREADY_PENDING
    }

    /**
     * 把当前状态整体写入磁盘。
     *
     * <p>先写同目录下的 .tmp,再用原子 move 覆盖正式文件:这样即使写到一半断电,
     * 也只会损坏临时文件,正式文件仍是上一个完整版本。ATOMIC_MOVE 在某些文件系统上
     * 不支持,所以捕获异常后退化为普通覆盖。</p>
     */
    private void save() throws IOException {
        Files.createDirectories(stateFile.getParent());
        Path temporary = stateFile.resolveSibling(stateFile.getFileName() + ".tmp");
        try (ObjectOutputStream output = new ObjectOutputStream(Files.newOutputStream(temporary))) {
            output.writeObject(this);
        }
        try {
            Files.move(temporary, stateFile, StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException ignored) {
            Files.move(temporary, stateFile, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    /** 单个账号。密码只保存盐和哈希;公钥会随每次登录更新 */
    private static final class Account implements Serializable {
        @Serial
        private static final long serialVersionUID = 1L;
        private final byte[] salt;
        private final byte[] passwordHash;
        private byte[] publicKey;

        private Account(byte[] salt, byte[] passwordHash, byte[] publicKey) {
            this.salt = salt;
            this.passwordHash = passwordHash;
            this.publicKey = publicKey;
        }
    }
}

package cipherchat.common;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

/**
 * 客户端与服务器之间传输的唯一消息载体。
 *
 * <p>两端都是 Java,所以直接用对象序列化(实现 {@link Serializable})走
 * ObjectOutputStream 收发,不必自己写编解码。所有字段都是 final,一个 Packet
 * 构造完成后就不会再被修改,避免在多线程环境里被改坏。</p>
 *
 * <p>这里采用"宽字段"写法:同一个类型承载登录、联系人、聊天等全部消息,
 * 用不到的字段留 null。好处是只需要维护一个类型,代价是字段含义要靠
 * {@link Type} 判断。下面的静态工厂方法规定了每种消息该填哪些字段。</p>
 */
public final class Packet implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    /** 消息类型。服务器收到包后按这个字段分发到不同的处理逻辑。 */
    public enum Type {
        /** 客户端 -> 服务器:注册新账号(用户名、密码、公钥) */
        REGISTER,
        /** 客户端 -> 服务器:登录已有账号 */
        LOGIN,
        /** 服务器 -> 客户端:鉴权通过 */
        AUTH_OK,
        /** 服务器 -> 客户端:鉴权失败,原因在 message 里 */
        AUTH_ERROR,
        /** 服务器 -> 客户端:联系人列表 + 各联系人公钥 + 在线状态 */
        USER_LIST,
        /** 服务器 -> 客户端:有人申请加你为联系人,需要弹窗让用户确认 */
        CONTACT_REQUEST,
        /** 客户端 -> 服务器:对联系人申请的应答(message 为 ACCEPT 或 REJECT) */
        CONTACT_RESPONSE,
        /** 服务器 -> 客户端:联系人相关的纯文本通知,显示在会话里 */
        CONTACT_EVENT,
        /** 双向:一对一聊天,正文是密文(iv + ciphertext) */
        CHAT,
        /** 服务器 -> 客户端:通用提示信息,例如"发送失败"的原因 */
        INFO
    }

    /** 消息类型,决定服务器如何处理这个包 */
    public final Type type;
    /** 鉴权用:用户名 */
    public final String username;
    /** 鉴权用:明文密码。只在登录/注册那一个包里出现,服务器校验完立刻丢弃,绝不落盘 */
    public final String password;
    /** 发送方用户名 */
    public final String from;
    /** 接收方用户名 */
    public final String to;
    /** 通用文本字段:CONTACT_RESPONSE 里是 ACCEPT/REJECT,提示类消息里是提示内容 */
    public final String message;
    /** 发送方的 X25519 公钥(编码后的字节),服务器存下来转交给需要与之通信的人 */
    public final byte[] publicKey;
    /** AES-GCM 的 12 字节随机初始向量,只属于 CHAT 消息 */
    public final byte[] iv;
    /** AES-GCM 密文(含 16 字节认证标签)。服务器只能看到它,看不到明文 */
    public final byte[] ciphertext;
    /** 消息产生时间(毫秒)。转发时由服务器统一盖章,防止客户端伪造时间 */
    public final long timestamp;
    /** USER_LIST 专用:联系人 -> 其公钥 的映射 */
    public final Map<String, byte[]> userKeys;
    /** USER_LIST 专用:当前在线的联系人集合 */
    public final Set<String> onlineUsers;

    /**
     * 私有构造器,统一在这里做 null 兜底,保证 userKeys / onlineUsers 永远不是 null,
     * 这样调用方可以放心遍历而不用先判空。对外只暴露下面几个工厂方法。
     */
    private Packet(Type type, String username, String password, String from, String to,
                   String message, byte[] publicKey, byte[] iv, byte[] ciphertext,
                   long timestamp, Map<String, byte[]> userKeys, Set<String> onlineUsers) {
        this.type = type;
        this.username = username;
        this.password = password;
        this.from = from;
        this.to = to;
        this.message = message;
        this.publicKey = publicKey;
        this.iv = iv;
        this.ciphertext = ciphertext;
        this.timestamp = timestamp;
        this.userKeys = userKeys == null ? Collections.emptyMap() : userKeys;
        this.onlineUsers = onlineUsers == null ? Collections.emptySet() : onlineUsers;
    }

    /** 登录/注册包。publicKey 是客户端本次会话的身份公钥,服务器会存下来供他人协商密钥。 */
    public static Packet auth(Type type, String username, String password, byte[] publicKey) {
        return new Packet(type, username, password, null, null, null, publicKey,
                null, null, 0, null, null);
    }

    /** 只带一段文字的状态包:AUTH_OK / AUTH_ERROR / INFO 使用。 */
    public static Packet status(Type type, String message) {
        return new Packet(type, null, null, null, null, message, null,
                null, null, 0, null, null);
    }

    /** 用户列表包:把联系人公钥表和在线的联系人一起发给客户端。 */
    public static Packet userList(Map<String, byte[]> keys, Set<String> onlineUsers) {
        return new Packet(Type.USER_LIST, null, null, null, null, null, null,
                null, null, 0, keys, onlineUsers);
    }

    /**
     * 聊天包。只装密文,不装明文,也不装发送者的公钥
     * (公钥已经通过 USER_LIST 提前分发,避免每条消息都重复携带)。
     */
    public static Packet chat(String from, String to, byte[] iv, byte[] ciphertext, long timestamp) {
        return new Packet(Type.CHAT, null, null, from, to, null, null,
                iv, ciphertext, timestamp, null, null);
    }

    /** 联系人相关的包:申请、应答、事件通知共用。时间戳取本机当前时间。 */
    public static Packet contact(Type type, String from, String to, String message) {
        return new Packet(type, null, null, from, to, message, null,
                null, null, System.currentTimeMillis(), null, null);
    }
}

package cipherchat.server;

import cipherchat.common.Packet;

import java.io.EOFException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 聊天服务器。整个服务端就是这一个类加上 {@link ServerState}。
 *
 * <p>并发模型:一个 {@link ServerSocket} 负责 accept,每个接入的连接交给一个
 * <b>虚拟线程</b>处理(见 {@link #clients})。虚拟线程是 JDK 21 的正式特性,
 * 阻塞式的 socket 读写不会占用平台线程,所以这里可以放心用最朴素的
 * "一个连接一个线程 + 阻塞读"写法,不必手写 NIO 状态机。</p>
 *
 * <p>服务器只做三件事:鉴权、转发密文、维护联系人和离线队列。
 * 它没有解密所需的私钥,所以永远看不到消息正文。</p>
 */
public final class ChatServer {
    private final int port;
    private final ServerState state;
    /** 在线用户表:用户名 -> 会话。并发读写,用 ConcurrentHashMap */
    private final Map<String, ClientSession> online = new ConcurrentHashMap<>();
    /** 每个连接一个虚拟线程。线程池负责回收,不需要显式关闭 */
    private final ExecutorService clients = Executors.newVirtualThreadPerTaskExecutor();

    /** 启动时把状态文件读回内存,路径是相对当前工作目录的 data/cipherchat-state.bin */
    private ChatServer(int port) {
        this.port = port;
        this.state = ServerState.load(Path.of("data", "cipherchat-state.bin"));
    }

    /** 入口。可选参数指定端口,默认 5050 */
    public static void main(String[] args) throws IOException {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 5050;
        new ChatServer(port).start();
    }

    /** 主循环:绑定端口后不断接受新连接,每个连接丢给一个虚拟线程 */
    private void start() throws IOException {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("CipherChat 服务器已启动，端口: " + port);
            System.out.println("状态文件: " + Path.of("data", "cipherchat-state.bin").toAbsolutePath());
            while (true) {
                Socket socket = serverSocket.accept();
                clients.submit(() -> handleClient(socket));
            }
        }
    }

    /**
     * 单个客户端的完整生命周期。
     *
     * <p>协议是"先鉴权后通信":连接建立后的第一个包必须是 REGISTER 或 LOGIN,
     * 之后才进入消息循环。这样未登录的连接不可能发消息或加好友。</p>
     *
     * <p>顺序很关键:鉴权成功后先推用户列表,再补发未处理的好友申请,
     * 最后投递离线消息——这样客户端拿到离线密文时,解密所需的对方公钥已经在本地了。</p>
     */
    private void handleClient(Socket socket) {
        String username = null;
        try (socket;
             ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream input = new ObjectInputStream(socket.getInputStream())) {
            output.flush();
            Packet request = (Packet) input.readObject();
            if (!validAuthRequest(request)) {
                send(output, Packet.status(Packet.Type.AUTH_ERROR, "用户名或密码格式不正确"));
                return;
            }

            boolean accepted = authenticate(request);
            if (!accepted) {
                String reason = request.type == Packet.Type.REGISTER ? "用户名已存在" : "用户名或密码错误";
                send(output, Packet.status(Packet.Type.AUTH_ERROR, reason));
                return;
            }

            username = request.username;
            // 同名账号重复登录时,踢掉旧连接,保证一个账号只占一个会话
            ClientSession previous = online.put(username, new ClientSession(socket, output));
            if (previous != null) {
                previous.close();
            }
            send(output, Packet.status(Packet.Type.AUTH_OK, "登录成功"));
            broadcastUserList();

            // 补发别人在离线期间发来的好友申请
            for (String requester : state.pendingRequests(username)) {
                send(output, Packet.contact(Packet.Type.CONTACT_REQUEST, requester, username, null));
            }

            // 投递离线消息。取走后服务端即删除,不会重复投递
            List<Packet> offline = state.takeOfflineMessages(username);
            for (Packet packet : offline) {
                send(output, packet);
            }

            // 消息循环:阻塞读,直到对方断开(抛 EOFException)或出错
            while (true) {
                Packet packet = (Packet) input.readObject();
                if (packet.type == Packet.Type.CHAT) {
                    routeChat(username, packet);
                } else if (packet.type == Packet.Type.CONTACT_REQUEST) {
                    handleContactRequest(username, packet);
                } else if (packet.type == Packet.Type.CONTACT_RESPONSE) {
                    handleContactResponse(username, packet);
                }
            }
        } catch (EOFException ignored) {
            // 客户端正常关闭窗口,不必当作错误
        } catch (IOException | ClassNotFoundException | GeneralSecurityException e) {
            System.err.println("客户端连接异常: " + e.getMessage());
        } finally {
            // 只有当 online 表里存的还是自己这条连接时才摘除,
            // 否则会把"同一账号新登录的那条连接"误删掉
            if (username != null) {
                ClientSession current = online.get(username);
                if (current != null && current.socket == socket) {
                    online.remove(username);
                    broadcastUserList();
                }
                System.out.println(username + " 已离线");
            }
        }
    }

    /** 按包类型决定是注册还是登录 */
    private boolean authenticate(Packet request) throws GeneralSecurityException, IOException {
        return request.type == Packet.Type.REGISTER
                ? state.register(request.username, request.password, request.publicKey)
                : state.authenticate(request.username, request.password, request.publicKey);
    }

    /**
     * 校验鉴权包格式。用户名和密码的规则必须与客户端一致,
     * 服务端不能只依赖客户端做校验。
     */
    private boolean validAuthRequest(Packet request) {
        if (request == null || (request.type != Packet.Type.LOGIN && request.type != Packet.Type.REGISTER)) {
            return false;
        }
        if (request.username == null || !request.username.matches("[a-zA-Z0-9_\\-\\u4e00-\\u9fa5]{2,20}")) {
            return false;
        }
        return request.password != null && request.password.length() >= 6 && request.password.length() <= 100
                && request.publicKey != null && request.publicKey.length > 0;
    }

    /**
     * 转发一条聊天消息。
     *
     * <p>安全要点:from 必须等于当前已鉴权的用户名,防止有人冒充他人发消息;
     * 且收发双方必须是联系人,否则任何人都能给任意账号发消息。</p>
     *
     * <p>时间戳由服务器重新盖章,客户端传来的时间只作参考。</p>
     */
    private void routeChat(String authenticatedUser, Packet packet) throws IOException {
        if (!authenticatedUser.equals(packet.from)) {
            // 身份与包里的 from 不符,属于伪造,直接丢弃且不回复,避免被当作探测工具
            return;
        }
        String reason;
        if (packet.to == null) {
            reason = "消息缺少接收方";
        } else if (!state.hasUser(packet.to)) {
            reason = "找不到用户 " + packet.to;
        } else if (!state.areContacts(authenticatedUser, packet.to)) {
            reason = packet.to + " 还不是你的联系人,请先添加好友并等对方同意";
        } else if (packet.iv == null || packet.ciphertext == null) {
            reason = "消息格式不正确";
        } else {
            reason = null;
        }
        if (reason != null) {
            // 这里以前是静默 return:发送方界面上显示"已发送",对方却永远收不到,
            // 很难排查。现在把原因回给发送方,让失败在界面上立刻可见。
            sendInfo(authenticatedUser, "消息未送出: " + reason);
            return;
        }
        Packet normalized = Packet.chat(authenticatedUser, packet.to, packet.iv, packet.ciphertext,
                System.currentTimeMillis());
        ClientSession recipient = online.get(packet.to);
        if (recipient == null) {
            // 对方离线:先存起来,等他登录再投递
            state.queueMessage(normalized);
        } else {
            try {
                recipient.send(normalized);
            } catch (IOException e) {
                // 写失败说明这条连接实际上已经不可用,降级为离线消息
                online.remove(packet.to, recipient);
                state.queueMessage(normalized);
                broadcastUserList();
            }
        }
    }

    /**
     * 处理加好友申请。用户填的是用户名,这里把各种失败情况翻译成明确文案,
     * 并只把申请推给在线的对方(不在线则留在服务端,登录时补发)。
     */
    private void handleContactRequest(String authenticatedUser, Packet packet) throws IOException {
        if (!authenticatedUser.equals(packet.from) || packet.to == null) {
            return;
        }
        ServerState.ContactRequestResult result = state.addContactRequest(authenticatedUser, packet.to);
        String message = switch (result) {
            case CREATED -> "联系人申请已发送给 " + packet.to;
            case USER_NOT_FOUND -> "找不到用户 " + packet.to;
            case SELF -> "不能添加自己为联系人";
            case ALREADY_CONTACTS -> packet.to + " 已经是你的联系人";
            case ALREADY_PENDING -> "申请已经发送，请等待对方处理";
        };
        ClientSession sender = online.get(authenticatedUser);
        if (sender != null) {
            sender.send(Packet.contact(Packet.Type.CONTACT_EVENT, "系统", authenticatedUser, message));
        }
        if (result == ServerState.ContactRequestResult.CREATED) {
            ClientSession recipient = online.get(packet.to);
            if (recipient != null) {
                recipient.send(Packet.contact(Packet.Type.CONTACT_REQUEST,
                        authenticatedUser, packet.to, null));
            }
        }
    }

    /**
     * 处理加好友的应答。只有真的存在这条申请才会生效。
     * 同意后双向建立联系人关系,并给双方都推一次新的用户列表,
     * 这样两台客户端都能立刻在列表里看到对方。
     */
    private void handleContactResponse(String authenticatedUser, Packet packet) throws IOException {
        if (!authenticatedUser.equals(packet.from) || packet.to == null) {
            return;
        }
        boolean accepted = "ACCEPT".equals(packet.message);
        boolean handled = state.respondToContactRequest(authenticatedUser, packet.to, accepted);
        if (!handled) {
            return;
        }
        String receiverMessage = accepted
                ? "你已添加 " + packet.to + " 为联系人"
                : "你已拒绝 " + packet.to + " 的联系人申请";
        ClientSession receiver = online.get(authenticatedUser);
        if (receiver != null) {
            receiver.send(Packet.contact(Packet.Type.CONTACT_EVENT, "系统", authenticatedUser, receiverMessage));
        }
        ClientSession requester = online.get(packet.to);
        if (requester != null) {
            String requesterMessage = accepted
                    ? authenticatedUser + " 已同意你的联系人申请"
                    : authenticatedUser + " 已拒绝你的联系人申请";
            requester.send(Packet.contact(Packet.Type.CONTACT_EVENT, "系统", packet.to, requesterMessage));
        }
        if (accepted) {
            sendUserList(authenticatedUser);
            sendUserList(packet.to);
        }
    }

    /** 有人的上线/离线状态变化时,刷新所有在线用户的联系人列表 */
    private void broadcastUserList() {
        online.keySet().forEach(this::sendUserList);
    }

    /**
     * 给某人推一份联系人列表。
     *
     * <p>列表里只包含<b>已成为联系人</b>的人及其公钥,以及其中谁在线。
     * 客户端只有拿到公钥才能加密,所以未通过好友申请的人不会出现在列表里。</p>
     */
    private void sendUserList(String username) {
        ClientSession session = online.get(username);
        if (session == null) {
            return;
        }
        Map<String, byte[]> keys = state.contactPublicKeys(username);
        Set<String> contactOnline = new java.util.HashSet<>(keys.keySet());
        contactOnline.retainAll(online.keySet());
        try {
            session.send(Packet.userList(keys, Set.copyOf(contactOnline)));
        } catch (IOException e) {
            session.close();
            online.remove(username, session);
        }
    }

    /**
     * 给在线用户发一条纯文本提示。
     * 用于把服务端拒绝的原因反馈到界面上,而不是让发送方一直不知情。
     */
    private void sendInfo(String username, String message) {
        ClientSession session = online.get(username);
        if (session == null) {
            return;
        }
        try {
            session.send(Packet.status(Packet.Type.INFO, message));
        } catch (IOException e) {
            session.close();
            online.remove(username, session);
        }
    }

    /**
     * 向某个连接写包。ObjectOutputStream 跨线程不安全,所以加锁串行化。
     * reset() 用来清空对象流缓存,避免服务端持续持有大量已发送对象的引用而内存上涨。
     */
    private static void send(ObjectOutputStream output, Packet packet) throws IOException {
        synchronized (output) {
            output.writeObject(packet);
            output.flush();
            output.reset();
        }
    }

    /** 一条已登录连接的会话句柄:记住 socket 和它的输出流 */
    private static final class ClientSession {
        private final Socket socket;
        private final ObjectOutputStream output;

        private ClientSession(Socket socket, ObjectOutputStream output) {
            this.socket = socket;
            this.output = output;
        }

        private void send(Packet packet) throws IOException {
            ChatServer.send(output, packet);
        }

        private void close() {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }
    }
}

package cipherchat.client;

import cipherchat.common.Packet;
import cipherchat.crypto.CryptoService;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.DefaultListCellRenderer;
import javax.swing.DefaultListModel;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;
import javax.swing.text.DefaultCaret;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Image;
import java.awt.Insets;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.net.ConnectException;
import java.net.URL;
import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 客户端主窗口。整个界面用一个 {@link CardLayout} 在"登录页"和"聊天页"之间切换。
 *
 * <p>线程模型:Swing 的界面操作只能在事件分发线程(EDT)上做,而网络读写会阻塞,
 * 所以所有网络动作都丢到虚拟线程里执行,拿到结果再用
 * {@link SwingUtilities#invokeLater} 切回 EDT 更新界面。本类里出现
 * {@code invokeLater} 的地方都是在做这件事。</p>
 *
 * <p>密钥归属:加密用的长期私钥保存在本机({@link CryptoService}),登录时随鉴权包
 * 上传公钥,私钥永不出本机。所以服务器和其他客户端都拿不到解密能力。</p>
 */
public final class CipherChatClient extends JFrame {
    // 界面配色:浅灰底 + 白面板 + 墨绿主色,避免大面积纯色
    private static final Color BG = new Color(244, 247, 250);
    private static final Color PANEL = Color.WHITE;
    private static final Color INK = new Color(31, 41, 55);
    private static final Color MUTED = new Color(107, 114, 128);
    private static final Color ACCENT = new Color(35, 112, 104);
    private static final Color ACCENT_DARK = new Color(25, 83, 77);
    private static final Color BORDER = new Color(222, 228, 235);
    /** 消息时间统一按本机时区显示为 HH:mm */
    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm")
            .withZone(ZoneId.systemDefault());

    /** 主卡片容器:"login" 是登录页,"chat" 是聊天页 */
    private final CardLayout cards = new CardLayout();
    private final JPanel root = new JPanel(cards);
    /** 登录页输入项。默认连本机 5050 端口 */
    private final JTextField hostField = new JTextField("127.0.0.1");
    private final JTextField portField = new JTextField("5050");
    private final JTextField usernameField = new JTextField();
    private final JPasswordField passwordField = new JPasswordField();
    private final JLabel loginStatus = new JLabel(" ");

    /** 左侧列表只显示"已成为联系人"的人,不是全部注册用户 */
    private final DefaultListModel<String> usersModel = new DefaultListModel<>();
    private final JList<String> usersList = new JList<>(usersModel);
    private final JLabel conversationTitle = new JLabel("选择一位联系人");
    private final JLabel encryptionLabel = new JLabel("端到端加密");
    private final JTextArea transcript = new JTextArea();
    private final JTextArea messageInput = new JTextArea(3, 20);
    private final JButton sendButton = new JButton("发送");
    private final JLabel currentUserLabel = new JLabel();
    private final JButton addContactButton = new JButton("+ 添加联系人");

    /**
     * 联系人 -> 对方公钥。这是加密的前提,由服务器通过 USER_LIST 包下发,
     * 只包含已通过好友申请的人。
     */
    private final Map<String, byte[]> publicKeys = new HashMap<>();
    /** 当前在线的联系人,用来在列表上显示 ● / ○ */
    private final Set<String> onlineUsers = new HashSet<>();
    /**
     * 本地的会话记录:对方用户名 -> 消息列表。
     *
     * <p>注意:这份聊天记录<b>只存在内存里,不落盘</b>。客户端关闭或重新登录后,
     * 历史消息就没了(服务端只保留"对方离线期间"尚未投递的密文)。
     * 这是当前原型的已知限制,不是 bug。</p>
     */
    private final Map<String, List<ChatLine>> conversations = new HashMap<>();
    private ClientConnection connection;
    private KeyPair keyPair;
    private String username;
    /** 当前正在查看哪个联系人的会话。发送时以它作为收件人 */
    private String activePeer;

    /** 入口:先套用系统外观,再在 EDT 上创建并显示窗口 */
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            setSystemLookAndFeel();
            CipherChatClient client = new CipherChatClient();
            client.setVisible(true);
        });
    }

    /** 构造窗口:注册两张卡片,并挂上关闭时的连接清理逻辑 */
    private CipherChatClient() {
        super("CipherChat 加密聊天室");
        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        setMinimumSize(new Dimension(900, 620));
        setSize(1060, 700);
        setLocationRelativeTo(null);
        setIconImage(loadAppIcon(128));

        root.add(buildLoginPanel(), "login");
        root.add(buildChatPanel(), "chat");
        setContentPane(root);

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent event) {
                // 先关 socket 再 dispose,让服务端能立刻感知到下线
                if (connection != null) {
                    connection.close();
                }
                dispose();
            }
        });
    }

    /**
     * 登录页:服务器地址、端口、用户名、密码,以及注册/登录两个按钮。
     * 注册和登录走的是同一套网络流程,只是包类型不同。
     */
    private JPanel buildLoginPanel() {
        JPanel page = new JPanel(new GridBagLayout());
        page.setBackground(BG);

        JPanel card = new JPanel(new GridBagLayout());
        card.setPreferredSize(new Dimension(450, 545));
        card.setBackground(PANEL);
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(BORDER), new EmptyBorder(28, 38, 30, 38)));

        GridBagConstraints c = constraints();
        ImageIcon logo = new ImageIcon(loadAppIcon(112));
        JLabel logoLabel = new JLabel(logo);
        c.gridwidth = 2;
        c.anchor = GridBagConstraints.CENTER;
        c.insets = new Insets(0, 0, 12, 0);
        card.add(logoLabel, c);

        c.gridy++;
        JLabel title = new JLabel("CipherChat");
        title.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 28));
        title.setForeground(INK);
        card.add(title, c);

        c.gridy++;
        c.insets = new Insets(4, 0, 24, 0);
        JLabel subtitle = new JLabel("消息在你的设备上加密");
        subtitle.setForeground(MUTED);
        card.add(subtitle, c);

        addField(card, c, "服务器", hostField, 0);
        addField(card, c, "端口", portField, 1);
        addField(card, c, "用户名", usernameField, 0);
        addField(card, c, "密码", passwordField, 1);

        c.gridy++;
        c.gridwidth = 2;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = new Insets(8, 0, 8, 0);
        JCheckBox showPassword = new JCheckBox("显示密码");
        showPassword.setOpaque(false);
        showPassword.setForeground(MUTED);
        showPassword.addActionListener(e -> passwordField.setEchoChar(showPassword.isSelected() ? '\0' : '\u2022'));
        card.add(showPassword, c);

        c.gridy++;
        c.insets = new Insets(4, 0, 8, 0);
        JPanel actions = new JPanel(new GridLayout(1, 2, 10, 0));
        actions.setOpaque(false);
        JButton registerButton = secondaryButton("注册");
        JButton loginButton = primaryButton("登录");
        registerButton.addActionListener(e -> authenticate(true, registerButton, loginButton));
        loginButton.addActionListener(e -> authenticate(false, registerButton, loginButton));
        passwordField.addActionListener(e -> authenticate(false, registerButton, loginButton));
        actions.add(registerButton);
        actions.add(loginButton);
        card.add(actions, c);

        c.gridy++;
        c.insets = new Insets(4, 0, 0, 0);
        loginStatus.setForeground(new Color(185, 28, 28));
        loginStatus.setHorizontalAlignment(JLabel.CENTER);
        card.add(loginStatus, c);

        page.add(card);
        return page;
    }

    /**
     * 聊天页:左侧联系人列表 + 右侧会话区(标题栏、消息区、输入区)。
     * 列表选中项变化时切换到对应会话。
     */
    private JPanel buildChatPanel() {
        JPanel page = new JPanel(new BorderLayout());
        page.setBackground(BG);

        JPanel sidebar = new JPanel(new BorderLayout());
        sidebar.setBackground(new Color(31, 47, 55));
        sidebar.setBorder(new EmptyBorder(18, 16, 16, 16));
        sidebar.setMinimumSize(new Dimension(235, 400));
        sidebar.setPreferredSize(new Dimension(270, 600));

        JPanel profile = new JPanel();
        profile.setLayout(new BoxLayout(profile, BoxLayout.X_AXIS));
        profile.setOpaque(false);
        JLabel avatar = new JLabel(new ImageIcon(loadAppIcon(46)));
        currentUserLabel.setForeground(Color.WHITE);
        currentUserLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 16));
        profile.add(avatar);
        profile.add(Box.createHorizontalStrut(12));
        profile.add(currentUserLabel);
        sidebar.add(profile, BorderLayout.NORTH);

        usersList.setBackground(new Color(31, 47, 55));
        usersList.setForeground(Color.WHITE);
        usersList.setSelectionBackground(new Color(48, 77, 82));
        usersList.setSelectionForeground(Color.WHITE);
        usersList.setFixedCellHeight(48);
        usersList.setBorder(new EmptyBorder(18, 0, 0, 0));
        usersList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        usersList.setCellRenderer(new UserRenderer());
        usersList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                openConversation(usersList.getSelectedValue());
            }
        });
        JScrollPane usersScroll = new JScrollPane(usersList);
        usersScroll.setBorder(null);
        usersScroll.getViewport().setBackground(new Color(31, 47, 55));
        sidebar.add(usersScroll, BorderLayout.CENTER);

        JPanel sidebarFooter = new JPanel(new BorderLayout());
        sidebarFooter.setOpaque(false);
        styleSidebarButton(addContactButton);
        addContactButton.addActionListener(e -> addContact());
        sidebarFooter.add(addContactButton, BorderLayout.CENTER);
        sidebar.add(sidebarFooter, BorderLayout.SOUTH);

        JPanel chat = new JPanel(new BorderLayout());
        chat.setBackground(PANEL);

        JPanel header = new JPanel(new BorderLayout());
        header.setBackground(PANEL);
        header.setBorder(new EmptyBorder(18, 24, 16, 24));
        conversationTitle.setForeground(INK);
        conversationTitle.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 19));
        encryptionLabel.setForeground(ACCENT);
        encryptionLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        header.add(conversationTitle, BorderLayout.WEST);
        header.add(encryptionLabel, BorderLayout.EAST);
        chat.add(header, BorderLayout.NORTH);

        transcript.setEditable(false);
        transcript.setLineWrap(true);
        transcript.setWrapStyleWord(true);
        transcript.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 15));
        transcript.setForeground(INK);
        transcript.setBackground(BG);
        transcript.setBorder(new EmptyBorder(18, 24, 18, 24));
        ((DefaultCaret) transcript.getCaret()).setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);
        JScrollPane transcriptScroll = new JScrollPane(transcript);
        transcriptScroll.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 0, BORDER));
        chat.add(transcriptScroll, BorderLayout.CENTER);

        JPanel composer = new JPanel(new BorderLayout(12, 0));
        composer.setBackground(PANEL);
        composer.setBorder(new EmptyBorder(14, 18, 14, 18));
        messageInput.setLineWrap(true);
        messageInput.setWrapStyleWord(true);
        messageInput.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 15));
        messageInput.setBorder(new EmptyBorder(9, 11, 9, 11));
        JScrollPane inputScroll = new JScrollPane(messageInput);
        inputScroll.setBorder(BorderFactory.createLineBorder(BORDER));
        sendButton.setEnabled(false);
        stylePrimary(sendButton);
        sendButton.setPreferredSize(new Dimension(92, 44));
        sendButton.addActionListener(e -> sendMessage());
        composer.add(inputScroll, BorderLayout.CENTER);
        composer.add(sendButton, BorderLayout.EAST);
        chat.add(composer, BorderLayout.SOUTH);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, sidebar, chat);
        split.setDividerSize(1);
        split.setDividerLocation(270);
        split.setEnabled(false);
        page.add(split, BorderLayout.CENTER);
        return page;
    }

    /**
     * 注册或登录。
     *
     * <p>流程:本机加载/生成长�期密钥 -> 建立 TCP 连接 -> 发鉴权包 ->
     * 同步等一个回包判断成败。只有收到 AUTH_OK 才切到聊天页,
     * 并启动后台读线程接管后续所有消息。</p>
     *
     * <p>整段网络操作放在虚拟线程里,所以按钮先置灰、结束后根据结果恢复。</p>
     */
    private void authenticate(boolean register, JButton registerButton, JButton loginButton) {
        String host = hostField.getText().trim();
        String name = usernameField.getText().trim();
        String password = new String(passwordField.getPassword());
        int port;
        try {
            port = Integer.parseInt(portField.getText().trim());
        } catch (NumberFormatException e) {
            loginStatus.setText("端口必须是数字");
            return;
        }
        if (!name.matches("[a-zA-Z0-9_\\-\\u4e00-\\u9fa5]{2,20}")) {
            loginStatus.setText("用户名需为 2-20 位中文、字母、数字、_ 或 -");
            return;
        }
        if (password.length() < 6) {
            loginStatus.setText("密码至少 6 位");
            return;
        }

        registerButton.setEnabled(false);
        loginButton.setEnabled(false);
        loginStatus.setForeground(MUTED);
        loginStatus.setText("正在连接...");
        Thread.startVirtualThread(() -> {
            ClientConnection pending = null;
            try {
                KeyPair pendingKeyPair = CryptoService.loadOrCreateKeyPair(name);
                pending = new ClientConnection(host, port);
                Packet.Type type = register ? Packet.Type.REGISTER : Packet.Type.LOGIN;
                pending.send(Packet.auth(type, name, password, pendingKeyPair.getPublic().getEncoded()));
                Packet response = pending.readOne();
                if (response.type != Packet.Type.AUTH_OK) {
                    pending.close();
                    showAuthFailure(response.message, registerButton, loginButton);
                    return;
                }

                ClientConnection established = pending;
                SwingUtilities.invokeLater(() -> {
                    username = name;
                    keyPair = pendingKeyPair;
                    connection = established;
                    currentUserLabel.setText(name);
                    setTitle("CipherChat - " + name);
                    cards.show(root, "chat");
                    established.startReader(this::receivePacket, this::connectionLost);
                });
            } catch (Exception e) {
                if (pending != null) {
                    pending.close();
                }
                String message = e instanceof ConnectException
                        ? "无法连接服务器。请先运行“启动客户端.cmd”或“启动服务器.cmd”"
                        : "连接失败: " + friendlyError(e);
                showAuthFailure(message, registerButton, loginButton);
            }
        });
    }

    /** 鉴权失败:把原因写在登录页底部,并恢复两个按钮 */
    private void showAuthFailure(String message, JButton registerButton, JButton loginButton) {
        SwingUtilities.invokeLater(() -> {
            loginStatus.setForeground(new Color(185, 28, 28));
            loginStatus.setText(message);
            registerButton.setEnabled(true);
            loginButton.setEnabled(true);
        });
    }

    /**
     * 后台读线程的回调入口,已经切到 EDT。
     * 按包类型分发:用户列表刷新界面,聊天消息解密后入会话,联系人消息弹窗或提示。
     */
    private void receivePacket(Packet packet) {
        SwingUtilities.invokeLater(() -> {
            if (packet.type == Packet.Type.USER_LIST) {
                publicKeys.clear();
                publicKeys.putAll(packet.userKeys);
                onlineUsers.clear();
                onlineUsers.addAll(packet.onlineUsers);
                refreshUserList();
            } else if (packet.type == Packet.Type.CHAT) {
                receiveChat(packet);
            } else if (packet.type == Packet.Type.CONTACT_REQUEST) {
                receiveContactRequest(packet);
            } else if (packet.type == Packet.Type.CONTACT_EVENT) {
                showSystemMessage(packet.message);
            } else if (packet.type == Packet.Type.INFO) {
                // 服务器拒绝了某个操作(例如发消息时双方还不是联系人)时给出的提示
                showSystemMessage(packet.message);
            }
        });
    }

    /**
     * 弹输入框问对方用户名,发出加好友申请。
     * 真正建立联系人关系需要对方在弹窗里同意,本机列表在此之前不会出现对方。
     */
    private void addContact() {
        String contact = JOptionPane.showInputDialog(this, "输入对方用户名：", "添加联系人",
                JOptionPane.PLAIN_MESSAGE);
        if (contact == null || contact.isBlank()) {
            return;
        }
        contact = contact.trim();
        String target = contact;
        Thread.startVirtualThread(() -> {
            try {
                connection.send(Packet.contact(Packet.Type.CONTACT_REQUEST, username, target, null));
            } catch (IOException e) {
                SwingUtilities.invokeLater(() -> showSystemMessage("发送联系人申请失败: " + friendlyError(e)));
            }
        });
    }

    /** 收到别人的加好友申请:弹确认框,把用户的选择作为应答发回服务器 */
    private void receiveContactRequest(Packet packet) {
        String requester = packet.from;
        int choice = JOptionPane.showConfirmDialog(this,
                requester + " 请求添加你为联系人，是否同意？", "新的联系人申请",
                JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
        String response = choice == JOptionPane.YES_OPTION ? "ACCEPT" : "REJECT";
        Thread.startVirtualThread(() -> {
            try {
                connection.send(Packet.contact(Packet.Type.CONTACT_RESPONSE, username, requester, response));
            } catch (IOException e) {
                SwingUtilities.invokeLater(() -> showSystemMessage("处理联系人申请失败: " + friendlyError(e)));
            }
        });
    }

    /**
     * 把一条系统提示追加到当前会话末尾。
     * 目前不区分会话,统一切到当前显示的会话里。
     */
    private void showSystemMessage(String message) {
        if (message == null || message.isBlank()) {
            return;
        }
        String previous = transcript.getText();
        if (!previous.isBlank() && !previous.endsWith("\n")) {
            previous += "\n";
        }
        transcript.setText(previous + "系统  " + TIME.format(Instant.now()) + "\n" + message + "\n\n");
        transcript.setCaretPosition(transcript.getDocument().getLength());
    }

    /**
     * 收到一条聊天消息:用对方公钥 + 自己私钥解出明文,存进本地会话。
     *
     * <p>解密失败不会崩,而是显示一条"无法解密"的提示——常见原因是
     * 对方换了设备或删了私钥重新生成了密钥,导致旧密文无法还原。</p>
     */
    private void receiveChat(Packet packet) {
        byte[] peerKey = publicKeys.get(packet.from);
        if (peerKey == null) {
            return;
        }
        try {
            PublicKey publicKey = CryptoService.decodePublicKey(peerKey);
            String plaintext = CryptoService.decrypt(packet.iv, packet.ciphertext,
                    keyPair.getPrivate(), publicKey, packet.from, packet.to);
            conversations.computeIfAbsent(packet.from, ignored -> new ArrayList<>())
                    .add(new ChatLine(packet.from, plaintext, packet.timestamp));
            if (packet.from.equals(activePeer)) {
                renderConversation();
            } else {
                usersList.repaint();
            }
        } catch (Exception e) {
            conversations.computeIfAbsent(packet.from, ignored -> new ArrayList<>())
                    .add(new ChatLine("系统", "[无法解密此消息，可能来自另一台设备的旧密钥]", packet.timestamp));
        }
    }

    /**
     * 发送消息:加密后交给连接发送,成功则把明文追加到本地会话(本地回显)。
     *
     * <p>发送前必须先有对方公钥,也就是双方已经互加好友。</p>
     */
    private void sendMessage() {
        String text = messageInput.getText().trim();
        if (activePeer == null || text.isEmpty()) {
            return;
        }
        byte[] peerKey = publicKeys.get(activePeer);
        if (peerKey == null) {
            JOptionPane.showMessageDialog(this, "对方公钥尚不可用", "无法发送", JOptionPane.WARNING_MESSAGE);
            return;
        }
        String peer = activePeer;
        messageInput.setText("");
        sendButton.setEnabled(false);
        Thread.startVirtualThread(() -> {
            try {
                PublicKey publicKey = CryptoService.decodePublicKey(peerKey);
                CryptoService.EncryptedMessage encrypted = CryptoService.encrypt(text,
                        keyPair.getPrivate(), publicKey, username, peer);
                long timestamp = System.currentTimeMillis();
                connection.send(Packet.chat(username, peer, encrypted.iv(), encrypted.ciphertext(), timestamp));
                SwingUtilities.invokeLater(() -> {
                    conversations.computeIfAbsent(peer, ignored -> new ArrayList<>())
                            .add(new ChatLine(username, text, timestamp));
                    if (peer.equals(activePeer)) {
                        renderConversation();
                    }
                    sendButton.setEnabled(true);
                    messageInput.requestFocusInWindow();
                });
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    sendButton.setEnabled(true);
                    JOptionPane.showMessageDialog(this, "发送失败: " + friendlyError(e),
                            "发送失败", JOptionPane.ERROR_MESSAGE);
                });
            }
        });
    }

    /**
     * 用服务器下发的最新数据重建左侧列表:排除自己,在线的排前面,
     * 其余按名称排序;并尽量保留用户当前选中的联系人。
     */
    private void refreshUserList() {
        String selection = usersList.getSelectedValue();
        List<String> names = publicKeys.keySet().stream()
                .filter(name -> !name.equals(username))
                .sorted(Comparator.comparing((String name) -> !onlineUsers.contains(name))
                        .thenComparing(name -> name.toLowerCase(java.util.Locale.ROOT)))
                .toList();
        usersModel.clear();
        names.forEach(usersModel::addElement);
        if (selection != null && names.contains(selection)) {
            usersList.setSelectedValue(selection, true);
        }
    }

    /** 切换到某个联系人的会话。传 null 表示清空右侧区域 */
    private void openConversation(String peer) {
        activePeer = peer;
        if (peer == null) {
            conversationTitle.setText("选择一位联系人");
            transcript.setText("");
            sendButton.setEnabled(false);
            return;
        }
        conversationTitle.setText(peer + (onlineUsers.contains(peer) ? " · 在线" : " · 离线"));
        encryptionLabel.setText("AES-GCM 端到端加密");
        sendButton.setEnabled(true);
        renderConversation();
        messageInput.requestFocusInWindow();
    }

    /** 把当前联系人的全部消息重新渲染到消息区,自动滚到底部 */
    private void renderConversation() {
        StringBuilder text = new StringBuilder();
        for (ChatLine line : conversations.getOrDefault(activePeer, List.of())) {
            String sender = line.sender.equals(username) ? "我" : line.sender;
            text.append(sender).append("  ").append(TIME.format(Instant.ofEpochMilli(line.timestamp)))
                    .append("\n").append(line.text).append("\n\n");
        }
        if (text.isEmpty()) {
            text.append("这是你们的加密会话。服务器无法读取消息正文。\n");
        }
        transcript.setText(text.toString());
        transcript.setCaretPosition(transcript.getDocument().getLength());
    }

    /** 连接断开:禁用发送按钮并提示用户 */
    private void connectionLost(Exception error) {
        SwingUtilities.invokeLater(() -> {
            sendButton.setEnabled(false);
            JOptionPane.showMessageDialog(this, "与服务器的连接已断开: " + friendlyError(error),
                    "连接断开", JOptionPane.WARNING_MESSAGE);
        });
    }

    /** GridBagLayout 的字段行:一列放标签、一列放输入框 */
    private static void addField(JPanel card, GridBagConstraints c, String label,
                                 javax.swing.JComponent field, int column) {
        if (column == 0) {
            c.gridy++;
        }
        c.gridx = column;
        c.gridwidth = 1;
        c.weightx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.WEST;
        c.insets = new Insets(column == 0 ? 6 : 6, column == 0 ? 0 : 7, 4, column == 0 ? 7 : 0);
        JPanel group = new JPanel(new BorderLayout(0, 5));
        group.setOpaque(false);
        JLabel fieldLabel = new JLabel(label);
        fieldLabel.setForeground(MUTED);
        fieldLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        field.setPreferredSize(new Dimension(140, 38));
        field.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(BORDER),
                new EmptyBorder(7, 9, 7, 9)));
        group.add(fieldLabel, BorderLayout.NORTH);
        group.add(field, BorderLayout.CENTER);
        card.add(group, c);
    }

    /** 统一的 GridBag 约束初始值 */
    private static GridBagConstraints constraints() {
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 0;
        c.weightx = 1;
        return c;
    }

    /** 主色按钮(墨绿实心) */
    private static JButton primaryButton(String text) {
        JButton button = new JButton(text);
        stylePrimary(button);
        return button;
    }

    private static void stylePrimary(JButton button) {
        button.setBackground(ACCENT);
        button.setForeground(Color.WHITE);
        button.setFocusPainted(false);
        button.setBorder(new EmptyBorder(10, 18, 10, 18));
        button.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 14));
    }

    /** 左侧边栏按钮样式 */
    private static void styleSidebarButton(JButton button) {
        button.setBackground(new Color(48, 77, 82));
        button.setForeground(Color.WHITE);
        button.setFocusPainted(false);
        button.setBorder(new EmptyBorder(10, 12, 10, 12));
        button.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 13));
    }

    /** 描边按钮(白底墨绿边),用于"注册"这类次要动作 */
    private static JButton secondaryButton(String text) {
        JButton button = new JButton(text);
        button.setBackground(Color.WHITE);
        button.setForeground(ACCENT_DARK);
        button.setFocusPainted(false);
        button.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(ACCENT),
                new EmptyBorder(9, 18, 9, 18)));
        button.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 14));
        return button;
    }

    /**
     * 从 classpath 加载应用图标并缩放到指定尺寸。
     * 图标缺失时返回一张透明占位图,保证界面仍能打开。
     */
    private static Image loadAppIcon(int size) {
        URL resource = CipherChatClient.class.getResource("/client-icon.png");
        if (resource == null) {
            return new java.awt.image.BufferedImage(size, size, java.awt.image.BufferedImage.TYPE_INT_ARGB);
        }
        return new ImageIcon(resource).getImage().getScaledInstance(size, size, Image.SCALE_SMOOTH);
    }

    /** 把异常转成适合展示的一行文字,避免界面出现 null */
    private static String friendlyError(Exception error) {
        String message = error.getMessage();
        return message == null || message.isBlank() ? error.getClass().getSimpleName() : message;
    }

    /** 使用操作系统原生的控件外观 */
    private static void setSystemLookAndFeel() {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {
        }
    }

    /** 一条本地会话记录:发送者、明文、时间戳 */
    private record ChatLine(String sender, String text, long timestamp) {
    }

    /** 联系人列表的渲染器:在线用绿点,离线用空心圆 */
    private final class UserRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                       boolean selected, boolean focused) {
            JLabel label = (JLabel) super.getListCellRendererComponent(list, value, index, selected, focused);
            String name = String.valueOf(value);
            label.setText((onlineUsers.contains(name) ? "●  " : "○  ") + name);
            label.setForeground(onlineUsers.contains(name) ? new Color(116, 220, 177) : new Color(180, 190, 196));
            if (selected) {
                label.setForeground(Color.WHITE);
            }
            label.setBorder(new EmptyBorder(0, 10, 0, 10));
            label.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 14));
            return label;
        }
    }
}

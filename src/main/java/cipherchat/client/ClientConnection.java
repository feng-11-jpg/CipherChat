package cipherchat.client;

import cipherchat.common.Packet;

import java.io.Closeable;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * 客户端与服务器之间的 TCP 长连接。
 *
 * <p>用 Java 对象流收发 {@link Packet},所以两端的 Packet 类必须完全一致。
 * 一条连接上会同时发生两件事:UI 线程往里写消息、一个读线程不断收消息。
 * 因为 ObjectOutputStream 不是线程安全的,写操作统一用 {@code synchronized}
 * 串行化;读只有读线程一个,不需要加锁。</p>
 *
 * <p>读取放在独立的虚拟线程里,是为了不阻塞 Swing 的事件分发线程,
 * 否则界面会在等待服务器回包时卡死。</p>
 */
final class ClientConnection implements Closeable {
    private final Socket socket;
    private final ObjectOutputStream output;
    private final ObjectInputStream input;
    /** 关闭标志。用它区分"用户正常关闭"和"真的断线",避免关窗口时误报错 */
    private final AtomicBoolean closed = new AtomicBoolean();
    private Thread readerThread;

    /** 建立连接。构造函数里先写一次 output.flush(),是对端 ObjectInputStream 完成握手的前提。 */
    ClientConnection(String host, int port) throws IOException {
        socket = new Socket(host, port);
        socket.setKeepAlive(true);
        output = new ObjectOutputStream(socket.getOutputStream());
        output.flush();
        input = new ObjectInputStream(socket.getInputStream());
    }

    /** 发送一个包。加锁保证多线程下不会写出交错的对象流。 */
    void send(Packet packet) throws IOException {
        synchronized (output) {
            output.writeObject(packet);
            output.flush();
            output.reset();
        }
    }

    /**
     * 只读一个包。
     * 目前只在登录握手阶段使用——那时需要同步等待服务器的 AUTH_OK / AUTH_ERROR。
     */
    Packet readOne() throws IOException, ClassNotFoundException {
        return (Packet) input.readObject();
    }

    /**
     * 启动后台读线程,收到包就回调 onPacket,出错回调 onError。
     * 登录成功后才调用,此后所有消息都从这个线程进来。
     */
    void startReader(Consumer<Packet> onPacket, Consumer<Exception> onError) {
        readerThread = Thread.startVirtualThread(() -> {
            try {
                while (!closed.get()) {
                    onPacket.accept((Packet) input.readObject());
                }
            } catch (Exception e) {
                if (!closed.get()) {
                    onError.accept(e);
                }
            }
        });
    }

    /** 关闭连接。cas 保证重复调用只真正关一次,也不会触发 onError 回调。 */
    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }
    }
}

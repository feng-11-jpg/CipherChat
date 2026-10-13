package cipherchat;

import cipherchat.common.Packet;
import cipherchat.crypto.CryptoService;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public final class SmokeTest {
    public static void main(String[] args) throws Exception {
        String suffix = Long.toString(System.nanoTime(), 36);
        String alice = "alice_" + suffix;
        String bob = "bob_" + suffix;
        KeyPair aliceKeys = KeyPairGenerator.getInstance("X25519").generateKeyPair();
        KeyPair bobKeys = KeyPairGenerator.getInstance("X25519").generateKeyPair();

        try (Connection a = new Connection(); Connection b = new Connection()) {
            a.send(Packet.auth(Packet.Type.REGISTER, alice, "password1", aliceKeys.getPublic().getEncoded()));
            require(a.read().type == Packet.Type.AUTH_OK, "Alice registration failed");
            a.readUntil(Packet.Type.USER_LIST);

            b.send(Packet.auth(Packet.Type.REGISTER, bob, "password2", bobKeys.getPublic().getEncoded()));
            require(b.read().type == Packet.Type.AUTH_OK, "Bob registration failed");
            b.readUntil(Packet.Type.USER_LIST);
            a.readUntil(Packet.Type.USER_LIST);

            a.send(Packet.contact(Packet.Type.CONTACT_REQUEST, alice, bob, null));
            Packet request = b.readUntil(Packet.Type.CONTACT_REQUEST);
            require(alice.equals(request.from) && bob.equals(request.to), "Contact request routing failed");
            b.send(Packet.contact(Packet.Type.CONTACT_RESPONSE, bob, alice, "ACCEPT"));
            b.readUntil(Packet.Type.USER_LIST);
            a.readUntil(Packet.Type.USER_LIST);

            String plaintext = "加密联调消息 " + suffix;
            var encrypted = CryptoService.encrypt(plaintext, aliceKeys.getPrivate(), bobKeys.getPublic(), alice, bob);
            a.send(Packet.chat(alice, bob, encrypted.iv(), encrypted.ciphertext(), System.currentTimeMillis()));
            Packet received = b.readUntil(Packet.Type.CHAT);
            String decrypted = CryptoService.decrypt(received.iv, received.ciphertext,
                    bobKeys.getPrivate(), aliceKeys.getPublic(), received.from, received.to);
            require(plaintext.equals(decrypted), "Decrypted message mismatch");
            System.out.println("SMOKE_TEST_OK: registration, contact request/acceptance, routing and AES-GCM decryption passed");
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }

    private static final class Connection implements AutoCloseable {
        private final Socket socket = new Socket("127.0.0.1", 5051);
        private final ObjectOutputStream output;
        private final ObjectInputStream input;

        private Connection() throws Exception {
            socket.setSoTimeout(5_000);
            output = new ObjectOutputStream(socket.getOutputStream());
            output.flush();
            input = new ObjectInputStream(socket.getInputStream());
        }

        private void send(Packet packet) throws Exception {
            output.writeObject(packet);
            output.flush();
            output.reset();
        }

        private Packet read() throws Exception {
            return (Packet) input.readObject();
        }

        private Packet readUntil(Packet.Type type) throws Exception {
            while (true) {
                Packet packet = read();
                if (packet.type == type) {
                    return packet;
                }
            }
        }

        @Override
        public void close() throws Exception {
            socket.close();
        }
    }
}

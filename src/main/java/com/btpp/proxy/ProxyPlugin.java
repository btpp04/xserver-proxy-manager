package com.btpp.proxy;

import org.bukkit.plugin.java.JavaPlugin;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ProxyPlugin extends JavaPlugin {

    private Logger logger;
    private ServerSocketChannel serverChannel;
    private Selector selector;
    private volatile boolean running = true;
    private final Map<SocketChannel, SocketChannel> channelMap = new HashMap<>();
    private int listenPort = 25575;

    @Override
    public void onEnable() {
        this.logger = getLogger();
        logger.info("XServer Proxy Manager 正在启动...");

        try {
            selector = Selector.open();
            serverChannel = ServerSocketChannel.open();
            serverChannel.configureBlocking(false);
            serverChannel.socket().bind(new InetSocketAddress(listenPort));
            serverChannel.register(selector, SelectionKey.OP_ACCEPT);

            logger.info("SOCKS5 代理已启动，监听端口: " + listenPort);

            Thread proxyThread = new Thread(this::proxyLoop);
            proxyThread.setDaemon(true);
            proxyThread.setName("SOCKS5-Proxy");
            proxyThread.start();

        } catch (IOException e) {
            logger.log(Level.SEVERE, "启动代理失败", e);
            getServer().getPluginManager().disablePlugin(this);
        }
    }

    @Override
    public void onDisable() {
        logger.info("XServer Proxy Manager 正在关闭...");
        running = false;

        try {
            if (serverChannel != null && serverChannel.isOpen()) {
                serverChannel.close();
            }
            if (selector != null && selector.isOpen()) {
                selector.close();
            }
        } catch (IOException e) {
            logger.log(Level.WARNING, "关闭代理时出错", e);
        }

        logger.info("XServer Proxy Manager 已关闭");
    }

    private void proxyLoop() {
        try {
            while (running && selector.isOpen()) {
                int n = selector.select(1000);
                if (n == 0) continue;

                Set<SelectionKey> selectedKeys = selector.selectedKeys();
                for (SelectionKey key : selectedKeys) {
                    try {
                        if (key.isAcceptable()) {
                            handleAccept(key);
                        } else if (key.isReadable()) {
                            handleRead(key);
                        }
                    } catch (IOException e) {
                        key.cancel();
                        key.channel().close();
                    }
                }
                selectedKeys.clear();
            }
        } catch (IOException e) {
            logger.log(Level.SEVERE, "代理循环出错", e);
        }
    }

    private void handleAccept(SelectionKey key) throws IOException {
        ServerSocketChannel server = (ServerSocketChannel) key.channel();
        SocketChannel clientChannel = server.accept();
        if (clientChannel != null) {
            clientChannel.configureBlocking(false);
            clientChannel.register(selector, SelectionKey.OP_READ);
        }
    }

    private void handleRead(SelectionKey key) throws IOException {
        SocketChannel channel = (SocketChannel) key.channel();
        ByteBuffer buffer = ByteBuffer.allocate(8192);
        int bytesRead = channel.read(buffer);

        if (bytesRead <= 0) {
            channel.close();
            key.cancel();
            channelMap.remove(channel);
            return;
        }

        buffer.flip();
        byte[] data = new byte[bytesRead];
        buffer.get(data);

        // 如果是客户端连接，先处理 SOCKS5 协议
        SocketChannel partner = channelMap.get(channel);
        if (partner == null && data.length > 0 && data[0] == 0x05) {
            handleSocks5Request(channel, data);
        } else if (partner != null) {
            // 转发数据到对端
            partner.write(ByteBuffer.wrap(data));
        }
    }

    private void handleSocks5Request(SocketChannel clientChannel, byte[] initialData) throws IOException {
        if (initialData.length < 4) return;

        byte version = initialData[0];
        byte method = initialData[1];

        if (version != 0x05) {
            ByteBuffer resp = ByteBuffer.wrap(new byte[]{0x05, 0xFF});
            clientChannel.write(resp);
            clientChannel.close();
            return;
        }

        if (method == 0x00) {
            ByteBuffer resp = ByteBuffer.wrap(new byte[]{0x05, 0x00});
            clientChannel.write(resp);

            // 读取 CONNECT 请求
            ByteBuffer connectBuf = ByteBuffer.allocate(1024);
            int bytesRead = clientChannel.read(connectBuf);
            if (bytesRead > 0) {
                connectBuf.flip();
                byte[] connectData = new byte[bytesRead];
                connectBuf.get(connectData);
                handleSocks5Connect(clientChannel, connectData);
            }
        } else {
            ByteBuffer resp = ByteBuffer.wrap(new byte[]{0x05, 0x02});
            clientChannel.write(resp);
        }
    }

    private void handleSocks5Connect(SocketChannel clientChannel, byte[] requestData) throws IOException {
        if (requestData.length < 7) return;

        byte version = requestData[0];
        byte cmd = requestData[1];
        byte atype = requestData[3];

        if (version != 0x05 || cmd != 0x01) {
            ByteBuffer resp = ByteBuffer.wrap(new byte[]{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
            clientChannel.write(resp);
            clientChannel.close();
            return;
        }

        String host;
        int port;

        switch (atype) {
            case 0x01: // IPv4
                if (requestData.length < 10) return;
                byte[] ipBytes = new byte[4];
                System.arraycopy(requestData, 4, ipBytes, 0, 4);
                host = InetAddress.getByAddress(ipBytes).getHostAddress();
                port = ((requestData[8] & 0xFF) << 8) | (requestData[9] & 0xFF);
                break;
            case 0x03: // Domain
                int domainLen = requestData[4] & 0xFF;
                if (requestData.length < 7 + domainLen) return;
                byte[] domainBytes = new byte[domainLen];
                System.arraycopy(requestData, 5, domainBytes, 0, domainLen);
                host = new String(domainBytes);
                port = ((requestData[5 + domainLen] & 0xFF) << 8) | (requestData[6 + domainLen] & 0xFF);
                break;
            case 0x04: // IPv6
                if (requestData.length < 22) return;
                byte[] ipv6Bytes = new byte[16];
                System.arraycopy(requestData, 4, ipv6Bytes, 0, 16);
                host = InetAddress.getByAddress(ipv6Bytes).getHostAddress();
                port = ((requestData[20] & 0xFF) << 8) | (requestData[21] & 0xFF);
                break;
            default:
                ByteBuffer resp = ByteBuffer.wrap(new byte[]{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
                clientChannel.write(resp);
                clientChannel.close();
                return;
        }

        logger.info("SOCKS5 CONNECT 请求: " + host + ":" + port);

        SocketChannel targetChannel = SocketChannel.open();
        targetChannel.configureBlocking(false);

        try {
            boolean connected = targetChannel.connect(new InetSocketAddress(host, port));
            if (!connected) {
                // 等待连接完成
                SelectionKey writeKey = targetChannel.register(selector, SelectionKey.OP_CONNECT);
                targetChannel.finishConnect();
            }

            ByteBuffer resp = ByteBuffer.wrap(new byte[]{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
            clientChannel.write(resp);

            // 建立双向映射
            channelMap.put(clientChannel, targetChannel);
            channelMap.put(targetChannel, clientChannel);

            targetChannel.register(selector, SelectionKey.OP_READ);
            logger.info("SOCKS5 连接已建立: " + host + ":" + port);

        } catch (IOException e) {
            ByteBuffer resp = ByteBuffer.wrap(new byte[]{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
            clientChannel.write(resp);
            clientChannel.close();
            targetChannel.close();
            logger.log(Level.WARNING, "SOCKS5 连接失败: " + host + ":" + port, e);
        }
    }
}

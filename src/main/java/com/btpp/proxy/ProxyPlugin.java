package com.btpp.proxy;

import io.papermc.paper.plugin.lifecycle.event.types.LifecycleEvents;
import org.bukkit.plugin.java.JavaPlugin;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ProxyPlugin extends JavaPlugin {

    private Logger logger;
    private ServerSocketChannel serverChannel;
    private Selector selector;
    private int listenPort = 25575;

    @Override
    public void onEnable() {
        this.logger = getLogger();
        logger.info("XServer Proxy Manager 正在启动...");

        try {
            // 初始化选择器
            selector = Selector.open();

            // 创建服务端通道
            serverChannel = ServerSocketChannel.open();
            serverChannel.configureBlocking(false);

            // 绑定端口
            serverChannel.socket().bind(new InetSocketAddress(listenPort));
            serverChannel.register(selector, SelectionKey.OP_ACCEPT);

            logger.info("SOCKS5 代理已启动，监听端口: " + listenPort);

            // 启动代理线程
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
            while (!selector.closed()) {
                int n = selector.select();
                if (n == 0) continue;

                Set<SelectionKey> selectedKeys = selector.selectedKeys();
                for (SelectionKey key : selectedKeys) {
                    if (key.isAcceptable()) {
                        handleAccept(key);
                    } else if (key.isReadable()) {
                        handleRead(key);
                    } else if (key.isWritable()) {
                        handleWrite(key);
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
            // 注册读取事件
            clientChannel.register(selector, SelectionKey.OP_READ);
            logger.info("客户端连接: " + clientChannel.socket().getRemoteSocketAddress());
        }
    }

    private void handleRead(SelectionKey key) throws IOException {
        SocketChannel clientChannel = (SocketChannel) key.channel();
        ByteBuffer buffer = ByteBuffer.allocate(8192);
        int bytesRead = clientChannel.read(buffer);

        if (bytesRead == -1) {
            // 连接关闭
            clientChannel.close();
            key.cancel();
            return;
        }

        buffer.flip();
        byte[] data = new byte[bytesRead];
        buffer.get(data);

        // 处理 SOCKS5 请求
        if (data.length > 0 && data[0] == 0x05) {
            handleSocks5Request(clientChannel, data);
        }
    }

    private void handleSocks5Request(SocketChannel clientChannel, byte[] initialData) throws IOException {
        // 解析 SOCKS5 请求
        if (initialData.length < 4) return;
        
        byte version = initialData[0];
        byte method = initialData[1];

        if (version != 0x05) {
            // 不支持的版本
            ByteBuffer resp = ByteBuffer.wrap(new byte[]{0x05, 0xFF});
            clientChannel.write(resp);
            clientChannel.close();
            return;
        }

        if (method == 0x00) {
            // 认证通过
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
            // 需要认证
            ByteBuffer resp = ByteBuffer.wrap(new byte[]{0x05, 0x02});
            clientChannel.write(resp);
        }
    }

    private void handleSocks5Connect(SocketChannel clientChannel, byte[] requestData) throws IOException {
        if (requestData.length < 7) return;

        byte version = requestData[0];
        byte cmd = requestData[1];
        byte reserved = requestData[2];
        byte atype = requestData[3];

        if (version != 0x05 || cmd != 0x01) {
            // 只支持 SOCKS5 CONNECT 命令
            ByteBuffer resp = ByteBuffer.wrap(new byte[]{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
            clientChannel.write(resp);
            clientChannel.close();
            return;
        }

        // 解析目标地址
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

        // 创建到目标地址的连接
        SocketChannel targetChannel = SocketChannel.open();
        targetChannel.configureBlocking(false);

        try {
            targetChannel.connect(new InetSocketAddress(host, port));
            
            // 等待连接完成
            if (targetChannel.finishConnect()) {
                // 连接成功
                ByteBuffer resp = ByteBuffer.wrap(new byte[]{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
                clientChannel.write(resp);
                
                // 注册双向通道
                targetChannel.register(selector, SelectionKey.OP_READ);
                clientChannel.register(selector, SelectionKey.OP_READ);
                
                // 保存通道对
                clientChannel.attach(targetChannel);
                targetChannel.attach(clientChannel);
                
                logger.info("SOCKS5 连接已建立: " + host + ":" + port);
            }
        } catch (IOException e) {
            // 连接失败
            ByteBuffer resp = ByteBuffer.wrap(new byte[]{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
            clientChannel.write(resp);
            clientChannel.close();
            targetChannel.close();
            logger.log(Level.WARNING, "SOCKS5 连接失败: " + host + ":" + port, e);
        }
    }

    private void handleWrite(SelectionKey key) throws IOException {
        // 写入处理在 read 中完成
    }
}
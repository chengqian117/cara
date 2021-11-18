package com.example.cara;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioSocketChannel;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

@Slf4j
public class NettyTest {

    @Test
    void rootInit() {
        EventLoopGroup eventLoopGroup = new NioEventLoopGroup();
        Channel channel=null;
        try{
            Bootstrap bootstrap = new Bootstrap();
            bootstrap.group(eventLoopGroup).channel(NioSocketChannel.class);
            bootstrap.option(ChannelOption.SO_KEEPALIVE, true); // (4)
//            bootstrap.handler(new ChannelInitializer<SocketChannel>() {
//                @Override
//                public void initChannel(SocketChannel ch) throws Exception {
//                    ch.pipeline().addLast(new MyClientHandler());
//                }
//            });



            ChannelFuture channelFuture = bootstrap.connect("172.16.10.220",1818).sync();

            // Wait until the connection is closed.
            channel = channelFuture.channel();


        } catch (InterruptedException e) {
            e.printStackTrace();
        } finally {
            eventLoopGroup.shutdownGracefully();
            if(null!=channel){
                channel.closeFuture();
            }
        }
    }
//    public static byte[] call(Channel channel, byte[] message) throws IOException {
//        ByteArrayOutputStream stream = new ByteArrayOutputStream();
//        int size = message.length;
//        stream.write((byte) (size >>> 8 & 0xFF));
//        stream.write((byte) (size & 0xFF));
//        stream.write(message);
//
//        channel.write(stream.toByteArray());
//        channel.flush();
//
//
//        final byte[] sizeLen = new byte[2];
//
//        if (size != 2) {
//            throw new IOException("The response head size error");
//        }
//        size = new BigInteger(1, sizeLen).intValue();
//        log.debug("返回长度:{}", size);
//        final byte[] buffer = new byte[size];
//        int readSize=0;
//        while (readSize < size) {
//            readSize += reader.read(buffer, readSize, size - readSize);
//        }
//
//        if (readSize != size) {
//            throw new IOException("Can not read all response");
//        }
//        return buffer;
//    }


//    class MyClientHandler extends SimpleChannelInboundHandler<String>{
//
//        @Override
//        protected void channelRead0(ChannelHandlerContext ctx, String msg) throws Exception {
//            //服务端的远程地址
//            System.out.println(ctx.channel().remoteAddress());
//            System.out.println("client output: "+msg);
//            ctx.writeAndFlush("from client: "+ LocalDateTime.now());
//        }
//
//        /**
//         * 当服务器端与客户端进行建立连接的时候会触发，如果没有触发读写操作，则客户端和客户端之间不会进行数据通信，也就是channelRead0不会执行，
//         * 当通道连接的时候，触发channelActive方法向服务端发送数据触发服务器端的handler的channelRead0回调，然后
//         * 服务端向客户端发送数据触发客户端的channelRead0，依次触发。
//         */
//        @Override
//        public void channelActive(ChannelHandlerContext ctx) throws Exception {
////            ctx.writeAndFlush("来自与客户端的问题!");
//        }
//
//        @Override
//        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
//            cause.printStackTrace();
//            ctx.close();
//        }
//    }



}

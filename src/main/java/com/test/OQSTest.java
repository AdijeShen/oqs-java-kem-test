package com.test;

import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import org.openjdk.jmh.runner.options.TimeValue;
import org.openquantumsafe.*;

import com.test.SM2KeyExchange.InitiatorKeyMaterial;
import com.test.SM2KeyExchange.ResponderKeyMaterial;
import com.test.*;
import com.test.HybridKeyExchange.InitiatorSession;
import com.test.HybridKeyExchange.ResponderSession;

public class OQSTest {
    static {
        try {
            // Seems like it doesn't need to load the lib.
            // String osName = System.getProperty("os.name").toLowerCase();
            // String libPath;
            // if (osName.contains("windows")) {
            // libPath = System.getProperty("user.dir") + "/lib/windows/oqs-jni.dll";
            // } else {
            // libPath = System.getProperty("user.dir") + "/lib/linux/liboqs-jni.so";
            // }
            // System.out.println("Loading native library: " + libPath);
            // System.load(libPath);
        } catch (UnsatisfiedLinkError e) {
            System.err.println("Native code library failed to load: " + e);
            System.exit(1);
        }
    }

    public static void main(String[] args) throws Exception {
        // // 测试量子安全KEM
        // testQuantumSafeKEM();

        // // 测试SM2密钥协商
        // testSM2KeyExchange();

        // // 测试混合密钥协商
        // HybridKeyExchange.testHybridKeyExchange();

        // // 测试混合密钥协商并使用SM4加密通信
        // HybridKeyExchange.testHybridKeyExchangeThenSM4Encrypt();

        Options opt = new OptionsBuilder()
                .include(HybridKeyExchangePerformanceTest.class.getSimpleName())
                .forks(1)
                .build();

        new Runner(opt).run();

    }

    private static void testQuantumSafeKEM() {
        System.out.println("\n=== Testing Quantum-Safe KEM ===");
        // 列出支持的KEM算法
        System.out.println("Supported KEMs:");
        for (String kem : KEMs.get_enabled_KEMs()) {
            System.out.println("- " + kem);
        }

        // 测试一个具体的KEM
        String kemName = "Kyber512";
        try {
            // 创建客户端和服务端的密钥对
            KeyEncapsulation client = new KeyEncapsulation(kemName);
            KeyEncapsulation server = new KeyEncapsulation(kemName);

            // 生成密钥对
            byte[] client_public_key = client.generate_keypair();

            // 使用客户端的公钥进行密钥封装
            Pair<byte[], byte[]> server_pair = server.encap_secret(client_public_key);
            byte[] ciphertext = server_pair.getLeft();
            byte[] shared_secret_server = server_pair.getRight();

            // 客户端解封装得到共享密钥
            byte[] shared_secret_client = client.decap_secret(ciphertext);

            // 验证双方得到的共享密钥是否相同
            boolean keysMatch = java.util.Arrays.equals(shared_secret_client, shared_secret_server);
            System.out.println("Test " + kemName + " - Keys match: " + keysMatch);

        } catch (RuntimeException e) {
            System.err.println(e.getMessage());
        }
    }

    private static void testSM2KeyExchange() {
        System.out.println("\n=== Testing SM2 Key Exchange ===");
        try {
            // 第一步：A初始化
            InitiatorKeyMaterial initiatorMaterial = SM2KeyExchange.initiatorInit();
            System.out.println("1. Initiator generated key pair and Ra");

            // 第二步：B响应
            ResponderKeyMaterial responderMaterial = SM2KeyExchange.responderResponse(
                    initiatorMaterial.publicKey,
                    initiatorMaterial.Ra);
            System.out.println("2. Responder generated key pair, Rb and calculated shared key");

            // 第三步：A计算共享密钥
            byte[] initiatorSharedKey = SM2KeyExchange.initiatorFinal(
                    initiatorMaterial,
                    responderMaterial.publicKey,
                    responderMaterial.Rb);
            System.out.println("3. Initiator calculated shared key");

            // 验证共享密钥是否匹配
            boolean keysMatch = java.util.Arrays.equals(initiatorSharedKey, responderMaterial.sharedKey);
            System.out.println("Shared keys match: " + keysMatch);
        } catch (Exception e) {
            System.err.println("SM2 Key Exchange failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

}

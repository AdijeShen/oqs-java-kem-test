package com.test;

import org.openquantumsafe.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;

public class HybridKeyExchange {
    public static class InitiatorSession {
        public final KeyEncapsulation kemClient;
        public final byte[] kemPublicKey;
        public final SM2KeyExchange.InitiatorKeyMaterial sm2Material;

        public InitiatorSession(KeyEncapsulation kemClient, byte[] kemPublicKey,
                SM2KeyExchange.InitiatorKeyMaterial sm2Material) {
            this.kemClient = kemClient;
            this.kemPublicKey = kemPublicKey;
            this.sm2Material = sm2Material;
        }
    }

    public static class ResponderSession {
        public final byte[] kemSharedSecret;
        public final byte[] kemCiphertext;
        public final SM2KeyExchange.ResponderKeyMaterial sm2Material;

        public ResponderSession(byte[] kemSharedSecret, byte[] kemCiphertext,
                SM2KeyExchange.ResponderKeyMaterial sm2Material) {
            this.kemSharedSecret = kemSharedSecret;
            this.kemCiphertext = kemCiphertext;
            this.sm2Material = sm2Material;
        }
    }

    public static void testHybridKeyExchange() {
        try {
            System.out.println("\n=== Testing Hybrid Key Exchange (ML-KEM-768 + SM2) ===");
            String kemName = "ML-KEM-768";

            // 第1步：发起方（A）初始化
            // 初始化ML-KEM-768
            KeyEncapsulation kemClient = new KeyEncapsulation(kemName);
            byte[] kemClientPublicKey = kemClient.generate_keypair();
            // 初始化SM2
            SM2KeyExchange.InitiatorKeyMaterial sm2InitiatorMaterial = SM2KeyExchange.initiatorInit();

            InitiatorSession initiatorSession = new InitiatorSession(
                    kemClient,
                    kemClientPublicKey,
                    sm2InitiatorMaterial);
            System.out.println("1. Initiator generated ML-KEM-768 keypair and SM2 parameters");

            /*
             * 模拟网络传输
             * A -> B: 发送
             * - ML-KEM-768公钥(kemClientPublicKey)
             * - SM2公钥(sm2InitiatorMaterial.publicKey)
             * - SM2 Ra点(sm2InitiatorMaterial.Ra)
             */

            // 第2步：响应方（B）处理
            // 处理ML-KEM-768
            KeyEncapsulation kemServer = new KeyEncapsulation(kemName);
            Pair<byte[], byte[]> serverPair = kemServer.encap_secret(kemClientPublicKey);
            byte[] kemCiphertext = serverPair.getLeft();
            byte[] kemSharedSecretServer = serverPair.getRight();

            // 处理SM2
            SM2KeyExchange.ResponderKeyMaterial sm2ResponderMaterial = SM2KeyExchange.responderResponse(
                    initiatorSession.sm2Material.publicKey,
                    initiatorSession.sm2Material.Ra);

            ResponderSession responderSession = new ResponderSession(
                    kemSharedSecretServer,
                    kemCiphertext,
                    sm2ResponderMaterial);
            System.out.println("2. Responder processed ML-KEM-768 and SM2 parameters");

            /*
             * 模拟网络传输
             * B -> A: 发送
             * - ML-KEM-768密文(kemCiphertext)
             * - SM2公钥(sm2ResponderMaterial.publicKey)
             * - SM2 Rb点(sm2ResponderMaterial.Rb)
             */

            // 第3步：发起方（A）完成密钥协商
            // 处理ML-KEM-768
            byte[] kemSharedSecretClient = initiatorSession.kemClient.decap_secret(responderSession.kemCiphertext);

            // 处理SM2
            byte[] sm2SharedKeyInitiator = SM2KeyExchange.initiatorFinal(
                    initiatorSession.sm2Material,
                    responderSession.sm2Material.publicKey,
                    responderSession.sm2Material.Rb);

            // 验证双方的密钥是否匹配
            boolean kemKeysMatch = Arrays.equals(kemSharedSecretClient, responderSession.kemSharedSecret);
            boolean sm2KeysMatch = Arrays.equals(sm2SharedKeyInitiator, responderSession.sm2Material.sharedKey);
            System.out.println("3. Key verification:");
            System.out.println("   ML-KEM-768 keys match: " + kemKeysMatch);
            System.out.println("   SM2 keys match: " + sm2KeysMatch);

            // 生成最终的混合密钥
            byte[] finalSharedKeyA = combineFinalKey(kemSharedSecretClient, sm2SharedKeyInitiator);
            byte[] finalSharedKeyB = combineFinalKey(responderSession.kemSharedSecret,
                    responderSession.sm2Material.sharedKey);

            boolean finalKeyMatch = Arrays.equals(finalSharedKeyA, finalSharedKeyB);
            System.out.println("4. Final hybrid shared key match: " + finalKeyMatch);

        } catch (Exception e) {
            System.err.println("Hybrid Key Exchange failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static void testHybridKeyExchangeThenSM4Encrypt() {
        try {
            System.out.println("\n=== Testing Hybrid Key Exchange (ML-KEM-768 + SM2) ===");
            String kemName = "ML-KEM-768";

            // 第1步：发起方（A）初始化
            // 初始化ML-KEM-768
            KeyEncapsulation kemClient = new KeyEncapsulation(kemName);
            byte[] kemClientPublicKey = kemClient.generate_keypair();
            // 初始化SM2
            SM2KeyExchange.InitiatorKeyMaterial sm2InitiatorMaterial = SM2KeyExchange.initiatorInit();

            InitiatorSession initiatorSession = new InitiatorSession(
                    kemClient,
                    kemClientPublicKey,
                    sm2InitiatorMaterial);
            System.out.println("1. Initiator generated ML-KEM-768 keypair and SM2 parameters");

            /*
             * 模拟网络传输
             * A -> B: 发送
             * - ML-KEM-768公钥(kemClientPublicKey)
             * - SM2公钥(sm2InitiatorMaterial.publicKey)
             * - SM2 Ra点(sm2InitiatorMaterial.Ra)
             */

            // 第2步：响应方（B）处理
            // 处理ML-KEM-768
            KeyEncapsulation kemServer = new KeyEncapsulation(kemName);
            Pair<byte[], byte[]> serverPair = kemServer.encap_secret(kemClientPublicKey);
            byte[] kemCiphertext = serverPair.getLeft();
            byte[] kemSharedSecretServer = serverPair.getRight();

            // 处理SM2
            SM2KeyExchange.ResponderKeyMaterial sm2ResponderMaterial = SM2KeyExchange.responderResponse(
                    initiatorSession.sm2Material.publicKey,
                    initiatorSession.sm2Material.Ra);

            ResponderSession responderSession = new ResponderSession(
                    kemSharedSecretServer,
                    kemCiphertext,
                    sm2ResponderMaterial);
            System.out.println("2. Responder processed ML-KEM-768 and SM2 parameters");

            /*
             * 模拟网络传输
             * B -> A: 发送
             * - ML-KEM-768密文(kemCiphertext)
             * - SM2公钥(sm2ResponderMaterial.publicKey)
             * - SM2 Rb点(sm2ResponderMaterial.Rb)
             */

            // 第3步：发起方（A）完成密钥协商
            // 处理ML-KEM-768
            byte[] kemSharedSecretClient = initiatorSession.kemClient.decap_secret(responderSession.kemCiphertext);

            // 处理SM2
            byte[] sm2SharedKeyInitiator = SM2KeyExchange.initiatorFinal(
                    initiatorSession.sm2Material,
                    responderSession.sm2Material.publicKey,
                    responderSession.sm2Material.Rb);

            // 验证双方的密钥是否匹配
            boolean kemKeysMatch = Arrays.equals(kemSharedSecretClient, responderSession.kemSharedSecret);
            boolean sm2KeysMatch = Arrays.equals(sm2SharedKeyInitiator, responderSession.sm2Material.sharedKey);
            System.out.println("3. Key verification:");
            System.out.println("   ML-KEM-768 keys match: " + kemKeysMatch);
            System.out.println("   SM2 keys match: " + sm2KeysMatch);

            // 生成最终的混合密钥
            byte[] finalSharedKeyA = combineFinalKey(kemSharedSecretClient, sm2SharedKeyInitiator);
            byte[] finalSharedKeyB = combineFinalKey(responderSession.kemSharedSecret,
                    responderSession.sm2Material.sharedKey);

            boolean finalKeyMatch = Arrays.equals(finalSharedKeyA, finalSharedKeyB);
            System.out.println("4. Final hybrid shared key match: " + finalKeyMatch);

            // A方：使用SM4加密消息

            // 准备测试消息
            String originalMessage = "Hello, this is a secret message from A to B!";
            System.out.println("Original message from A: " + originalMessage);

            byte[] sm4KeyA = Arrays.copyOf(finalSharedKeyA, 16); // SM4需要128位密钥
            byte[] iv = new byte[16]; // 初始化向量
            SM4Utils sm4 = new SM4Utils();
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            SM4Utils sm4Utils = new SM4Utils();
            byte[] encryptedData = sm4Utils.encrypt(originalMessage.getBytes(StandardCharsets.UTF_8), sm4KeyA, iv);

            System.out.println("Encrypted message (Base64): " + Base64.getEncoder().encodeToString(encryptedData));

            /*
             * 模拟网络传输
             * A -> B: 发送
             * - 加密后的消息(encryptedData)
             * - 初始化向量(iv)
             */

            // B方：使用SM4解密消息
            byte[] sm4KeyB = Arrays.copyOf(finalSharedKeyB, 16);
            byte[] decryptedData = sm4Utils.decrypt(encryptedData, sm4KeyB, iv);
            String decryptedMessage = new String(decryptedData, StandardCharsets.UTF_8);

            System.out.println("Decrypted message at B: " + decryptedMessage);
            System.out.println("Message successfully transmitted: " +
                    originalMessage.equals(decryptedMessage));

        } catch (Exception e) {
            System.err.println("Hybrid Key Exchange failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // 合并ML-KEM-768和SM2的共享密钥
    private static byte[] combineFinalKey(byte[] kemKey, byte[] sm2Key) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(kemKey);
            digest.update(sm2Key);
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }
}

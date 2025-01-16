package com.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.openquantumsafe.*;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.jce.ECNamedCurveTable;
import java.util.Arrays;

import com.test.SM2KeyExchange.InitiatorKeyMaterial;
import com.test.SM2KeyExchange.ResponderKeyMaterial;

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
        testSM4KeyEncryptionWithSM2();
        // // 测试SM2密钥协商
        // testSM2KeyExchange();

        // testDilithium();

        // // 测试混合密钥协商
        // HybridKeyExchange.testHybridKeyExchange();

        // // 测试混合密钥协商并使用SM4加密通信
        // HybridKeyExchange.testHybridKeyExchangeThenSM4Encrypt();

        // Options opt = new OptionsBuilder()
        // .include(HybridKeyExchangePerformanceTest.class.getSimpleName())
        // .resultFormat(ResultFormatType.JSON)
        // .result("benchmark-results.json")
        // .build();

        // new Runner(opt).run();

    }

    private static void testQuantumSafeKEM() {
        System.out.println("\n=== Testing Quantum-Safe KEM ===");
        // 列出支持的KEM算法
        System.out.println("Supported KEMs:");
        for (String kem : KEMs.get_enabled_KEMs()) {
            System.out.println("- " + kem);
        }

        // 测试一个具体的KEM
        String kemName = "ML-KEM-768";
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

            System.out.println("ML-KEM scheme, pk size is " + client_public_key.length + " bytes," + " ct size is "
                    + ciphertext.length + " bytes, ss size is " + shared_secret_client.length
                    + " bytes, sk size is " + client.export_secret_key().length + " bytes");

            // 验证双方得到的共享密钥是否相同
            boolean keysMatch = java.util.Arrays.equals(shared_secret_client, shared_secret_server);
            System.out.println("Test " + kemName + " - Keys match: " + keysMatch);

        } catch (RuntimeException e) {
            System.err.println(e.getMessage());
        }
    }

    private static void testSM4KeyEncryptionWithSM2() {
        System.out.println("\n=== Testing SM4 Key Encryption/Decryption with SM2 ===");
        try {
            // 1. 生成SM2公钥和私钥
            ECParameterSpec sm2Spec = ECNamedCurveTable.getParameterSpec("sm2p256v1");
            SecureRandom random = new SecureRandom();

            // 生成私钥
            BigInteger privateKeyValue = new BigInteger(256, random); // 生成一个随机的256位私钥
            ECPrivateKeyParameters privateKey = new ECPrivateKeyParameters(
                    privateKeyValue,
                    new org.bouncycastle.crypto.params.ECDomainParameters(sm2Spec.getCurve(), sm2Spec.getG(),
                            sm2Spec.getN()));

            // 生成公钥
            ECPoint Q = sm2Spec.getG().multiply(privateKeyValue);
            ECPublicKeyParameters publicKey = new ECPublicKeyParameters(
                    Q,
                    new org.bouncycastle.crypto.params.ECDomainParameters(sm2Spec.getCurve(), sm2Spec.getG(),
                            sm2Spec.getN()));

            System.out.println("Generated SM2 key pair.");
            System.out.println("Private Key: " + privateKeyValue.toString(16).length() / 2); // 输出私钥（十六进制形式）
            System.out.println("Public Key: " + Q.toString().length() / 2); // 输出公钥

            // 2. 生成随机的SM4密钥
            byte[] sm4Key = new byte[16]; // SM4 密钥大小为 128 位（16 字节）
            random.nextBytes(sm4Key);
            System.out.println("Generated random SM4 key: " + Arrays.toString(sm4Key));

            // 3. 使用SM2公钥加密SM4密钥
            SM2Engine sm2Engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
            sm2Engine.init(true, new ParametersWithRandom(publicKey, random));
            byte[] encryptedSM4Key = sm2Engine.processBlock(sm4Key, 0, sm4Key.length);
            System.out.println("Encrypted SM4 key: " + Arrays.toString(encryptedSM4Key));
            System.out.println("Encrypted SM4 key size: " + encryptedSM4Key.length + " bytes");

            // 4. 使用SM2私钥解密SM4密钥
            sm2Engine.init(false, privateKey);
            byte[] decryptedSM4Key = sm2Engine.processBlock(encryptedSM4Key, 0, encryptedSM4Key.length);
            System.out.println("Decrypted SM4 key: " + Arrays.toString(decryptedSM4Key));

            // 5. 验证解密后的SM4密钥与原始密钥是否一致
            boolean keysMatch = Arrays.equals(sm4Key, decryptedSM4Key);
            System.out.println("SM4 key encryption/decryption successful: " + keysMatch);

        } catch (Exception e) {
            System.err.println("SM4 Key Encryption/Decryption with SM2 failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void testDilithium() {
        System.out.println("\n=== Testing Dilithium ===");
        // 列出支持的签名算法

        System.out.println("Supported Signatures:");
        Sigs.get_supported_sigs().forEach(sig -> {
            System.out.println("- " + sig);
        });

        org.openquantumsafe.Signature sig = new org.openquantumsafe.Signature("Dilithium2");

        byte[] message = "Hello, world!".getBytes();
        byte[] pk = sig.generate_keypair();
        byte[] signature = sig.sign(message);
        boolean verified = sig.verify(message, signature, pk);
        System.out.println("Test Dilithium - Signature verified: " + verified);
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

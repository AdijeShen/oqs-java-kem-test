package com.test;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;

public class SM2KeyExchange {
    private static final X9ECParameters SM2_CURVE_PARAMS = GMNamedCurves.getByName("sm2p256v1");
    private static final ECDomainParameters DOMAIN_PARAMS = new ECDomainParameters(
            SM2_CURVE_PARAMS.getCurve(),
            SM2_CURVE_PARAMS.getG(),
            SM2_CURVE_PARAMS.getN(),
            SM2_CURVE_PARAMS.getH()
    );

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // 密钥对类
    public static class KeyPairWithR {
        public final AsymmetricCipherKeyPair keyPair;
        public final BigInteger r;
        public final ECPoint R;

        public KeyPairWithR(AsymmetricCipherKeyPair keyPair, BigInteger r, ECPoint R) {
            this.keyPair = keyPair;
            this.r = r;
            this.R = R;
        }
    }

    // 生成密钥对和临时参数
    private static KeyPairWithR generateKeyPairWithR() {
        // 生成密钥对
        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
        ECKeyGenerationParameters keyGenParams = new ECKeyGenerationParameters(DOMAIN_PARAMS, new SecureRandom());
        keyPairGenerator.init(keyGenParams);
        AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();

        // 生成随机数r和计算R点
        BigInteger r = new BigInteger(256, new SecureRandom());
        ECPoint R = DOMAIN_PARAMS.getG().multiply(r);

        return new KeyPairWithR(keyPair, r, R);
    }

    // 发起方（A方）的密钥材料
    public static class InitiatorKeyMaterial {
        public final ECPublicKeyParameters publicKey;
        public final ECPoint Ra;
        public final KeyPairWithR keyPairWithR;

        public InitiatorKeyMaterial(KeyPairWithR keyPairWithR) {
            this.keyPairWithR = keyPairWithR;
            this.publicKey = (ECPublicKeyParameters) keyPairWithR.keyPair.getPublic();
            this.Ra = keyPairWithR.R;
        }
    }

    // 响应方（B方）的密钥材料
    public static class ResponderKeyMaterial {
        public final ECPublicKeyParameters publicKey;
        public final ECPoint Rb;
        public final KeyPairWithR keyPairWithR;
        public final byte[] sharedKey;

        public ResponderKeyMaterial(KeyPairWithR keyPairWithR, ECPoint Rb, byte[] sharedKey) {
            this.keyPairWithR = keyPairWithR;
            this.publicKey = (ECPublicKeyParameters) keyPairWithR.keyPair.getPublic();
            this.Rb = Rb;
            this.sharedKey = sharedKey;
        }
    }

    // 第一步：发起方（A方）初始化
    public static InitiatorKeyMaterial initiatorInit() {
        KeyPairWithR keyPairWithR = generateKeyPairWithR();
        return new InitiatorKeyMaterial(keyPairWithR);
    }

    // 第二步：响应方（B方）响应
    public static ResponderKeyMaterial responderResponse(ECPublicKeyParameters initiatorPublicKey, ECPoint Ra) {
        // 生成B的密钥对和临时参数
        KeyPairWithR keyPairWithR = generateKeyPairWithR();
        ECPrivateKeyParameters privateKeyB = (ECPrivateKeyParameters) keyPairWithR.keyPair.getPrivate();

        // 计算共享密钥
        ECPoint y1 = initiatorPublicKey.getQ().multiply(keyPairWithR.r); // rB * PA
        ECPoint y2 = Ra.multiply(privateKeyB.getD()); // dB * RA
        byte[] sharedKey = y1.add(y2).normalize().getEncoded(false);

        return new ResponderKeyMaterial(keyPairWithR, keyPairWithR.R, sharedKey);
    }

    // 第三步：发起方（A方）计算共享密钥
    public static byte[] initiatorFinal(InitiatorKeyMaterial initiatorMaterial, 
                                      ECPublicKeyParameters responderPublicKey, 
                                      ECPoint Rb) {
        ECPrivateKeyParameters privateKeyA = (ECPrivateKeyParameters) initiatorMaterial.keyPairWithR.keyPair.getPrivate();

        // 计算共享密钥
        ECPoint x1 = responderPublicKey.getQ().multiply(initiatorMaterial.keyPairWithR.r); // rA * PB
        ECPoint x2 = Rb.multiply(privateKeyA.getD()); // dA * RB
        return x1.add(x2).normalize().getEncoded(false);
    }

    // 演示完整的密钥交换过程
    public static void demonstrateKeyExchange() {
        // 第一步：A初始化
        InitiatorKeyMaterial initiatorMaterial = initiatorInit();
        System.out.println("1. Initiator generated key pair and Ra");

        // 第二步：B响应
        ResponderKeyMaterial responderMaterial = responderResponse(
            initiatorMaterial.publicKey, 
            initiatorMaterial.Ra
        );
        System.out.println("2. Responder generated key pair, Rb and calculated shared key");

        // 第三步：A计算共享密钥
        byte[] initiatorSharedKey = initiatorFinal(
            initiatorMaterial,
            responderMaterial.publicKey,
            responderMaterial.Rb
        );
        System.out.println("3. Initiator calculated shared key");

        // 验证共享密钥是否匹配
        boolean keysMatch = java.util.Arrays.equals(initiatorSharedKey, responderMaterial.sharedKey);
        System.out.println("Shared keys match: " + keysMatch);
    }
}
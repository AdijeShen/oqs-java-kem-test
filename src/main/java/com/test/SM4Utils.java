package com.test;

import java.security.Security;
import java.util.Arrays;

import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

// 使用Bouncy Castle的SM4工具类
public class SM4Utils {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public byte[] encrypt(byte[] plaintext, byte[] key, byte[] iv) throws Exception {
        try {
            SM4Engine engine = new SM4Engine();
            CBCBlockCipher cbc = new CBCBlockCipher(engine);
            ParametersWithIV params = new ParametersWithIV(new KeyParameter(key), iv);
            
            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(cbc, new PKCS7Padding());
            cipher.init(true, params);

            byte[] outputBuffer = new byte[cipher.getOutputSize(plaintext.length)];
            int length = cipher.processBytes(plaintext, 0, plaintext.length, outputBuffer, 0);
            length += cipher.doFinal(outputBuffer, length);

            byte[] result = Arrays.copyOf(outputBuffer, length);
            return result;
        } catch (Exception e) {
            throw new Exception("SM4 encryption error", e);
        }
    }

    public byte[] decrypt(byte[] ciphertext, byte[] key, byte[] iv) throws Exception {
        try {
            SM4Engine engine = new SM4Engine();
            CBCBlockCipher cbc = new CBCBlockCipher(engine);
            ParametersWithIV params = new ParametersWithIV(new KeyParameter(key), iv);
            
            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(cbc, new PKCS7Padding());
            cipher.init(false, params);

            byte[] outputBuffer = new byte[cipher.getOutputSize(ciphertext.length)];
            int length = cipher.processBytes(ciphertext, 0, ciphertext.length, outputBuffer, 0);
            length += cipher.doFinal(outputBuffer, length);

            byte[] result = Arrays.copyOf(outputBuffer, length);
            return result;
        } catch (Exception e) {
            throw new Exception("SM4 decryption error", e);
        }
    }
}
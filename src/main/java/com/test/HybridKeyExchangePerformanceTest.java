package com.test;

import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Level;

import org.openquantumsafe.KeyEncapsulation;
import org.openquantumsafe.Pair;

import com.test.HybridKeyExchange.InitiatorSession;
import com.test.HybridKeyExchange.ResponderSession;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

// @BenchmarkMode({Mode.Throughput, Mode.AverageTime, Mode.SampleTime, Mode.SingleShotTime})
// @OutputTimeUnit(TimeUnit.MILLISECONDS)
// @Warmup(iterations = 5, time = 1)
// @Measurement(iterations = 5, time = 1)
// @Fork(3)
public class HybridKeyExchangePerformanceTest {

    // 添加内存使用监控
    @State(Scope.Thread)
    public static class MemoryState {
        long beforeMemory;
        long afterMemory;
        Runtime runtime;

        @Setup
        public void setup() {
            runtime = Runtime.getRuntime();
            System.gc();
            beforeMemory = runtime.totalMemory() - runtime.freeMemory();
        }

        @TearDown
        public void tearDown() {
            System.gc();
            afterMemory = runtime.totalMemory() - runtime.freeMemory();
            long memoryUsed = afterMemory - beforeMemory;
            System.out.println("Memory used: " + memoryUsed / 1024 + " KB");
            System.out.println("Total memory: " + runtime.totalMemory() / 1024 + " KB");
            System.out.println("Free memory: " + runtime.freeMemory() / 1024 + " KB");
        }
    }

    // 添加错误率统计
    @State(Scope.Benchmark)
    public static class ErrorState {
        AtomicInteger totalRequests = new AtomicInteger(0);
        AtomicInteger failedRequests = new AtomicInteger(0);

        public void recordSuccess() {
            totalRequests.incrementAndGet();
        }

        public void recordFailure() {
            totalRequests.incrementAndGet();
            failedRequests.incrementAndGet();
        }
    }

    // 添加延迟分布测试
    @Benchmark
    @BenchmarkMode(Mode.SampleTime)
    @OutputTimeUnit(TimeUnit.SECONDS)
    public void latencyDistributionTest(TestState state, MemoryState memoryState, ErrorState errorState)
            throws Exception {
        fullProcessTest(state,memoryState,errorState);
    }

    // 添加大并发测试
    @Benchmark
    @Threads(100)
    public void highConcurrencyTest(TestState state, MemoryState memoryState, ErrorState errorState) {
        try {
            fullProcessTest(state, memoryState, errorState);
            errorState.recordSuccess();
        } catch (Exception e) {
            errorState.recordFailure();
        }
    }

    // 添加持续负载测试
    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @Measurement(iterations = 10, time = 60)
    public void sustainedLoadTest(TestState state, MemoryState memoryState, ErrorState errorState) throws Exception {
        fullProcessTest(state, memoryState, errorState);
    }

    @State(Scope.Thread)
    public static class TestState {
        String kemName = "ML-KEM-768";
        String testMessage = "Hello, this is a secret message for performance testing!";
        KeyEncapsulation kemClient;
        KeyEncapsulation kemServer;
        byte[] kemClientPublicKey;
        SM2KeyExchange.InitiatorKeyMaterial sm2InitiatorMaterial;
        SecureRandom random;
        byte[] iv;
        byte[] kemCiphertext;

        // SM2 specific state
        ECPublicKeyParameters sm2InitiatorPublicKey;
        ECPoint sm2InitiatorRa;

        @Setup
        public void setup() {
            // ML-KEM setup
            kemClient = new KeyEncapsulation(kemName);
            kemServer = new KeyEncapsulation(kemName);
            kemClientPublicKey = kemClient.generate_keypair();

            // Generate ciphertext for decap testing
            Pair<byte[], byte[]> serverPair = kemServer.encap_secret(kemClientPublicKey);
            kemCiphertext = serverPair.getLeft();

            random = new SecureRandom();
            iv = new byte[16];
            random.nextBytes(iv);

            // SM2 setup
            sm2InitiatorMaterial = SM2KeyExchange.initiatorInit();
            sm2InitiatorPublicKey = sm2InitiatorMaterial.publicKey;
            sm2InitiatorRa = sm2InitiatorMaterial.Ra;
        }
    }

    // // 步骤1：初始化测试
    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    @Fork(value = 1, warmups = 2)
    @Warmup(iterations = 1)
    @Measurement(iterations = 3)
    public void initializationPhase(TestState state, MemoryState memoryState, ErrorState errorState) {
        KeyEncapsulation kemClient = new KeyEncapsulation(state.kemName);
        byte[] kemClientPublicKey = kemClient.generate_keypair();
        SM2KeyExchange.InitiatorKeyMaterial sm2InitiatorMaterial = SM2KeyExchange.initiatorInit();
    }

    // 步骤2：密钥交换测试
    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    @Fork(value = 1, warmups = 2)
    @Warmup(iterations = 1)
    @Measurement(iterations = 3)
    public void keyExchangePhase(TestState state, MemoryState memoryState, ErrorState errorState) {
        // 密钥交换逻辑

        // Initiator side
        InitiatorSession initiatorSession = new InitiatorSession(
                state.kemClient,
                state.kemClientPublicKey,
                state.sm2InitiatorMaterial);

        // Responder side
        Pair<byte[], byte[]> serverPair = state.kemServer.encap_secret(state.kemClientPublicKey);
        byte[] kemCiphertext = serverPair.getLeft();
        byte[] kemSharedSecretServer = serverPair.getRight();

        SM2KeyExchange.ResponderKeyMaterial sm2ResponderMaterial = SM2KeyExchange.responderResponse(
                initiatorSession.sm2Material.publicKey,
                initiatorSession.sm2Material.Ra);

        // Final key generation
        byte[] kemSharedSecretClient = initiatorSession.kemClient.decap_secret(kemCiphertext);
        byte[] sm2SharedKeyInitiator = SM2KeyExchange.initiatorFinal(
                initiatorSession.sm2Material,
                sm2ResponderMaterial.publicKey,
                sm2ResponderMaterial.Rb);
    }

    // 步骤3：加密解密测试
    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    @Fork(value = 1, warmups = 2)
    @Warmup(iterations = 1)
    @Measurement(iterations = 3)
    public void encryptionDecryptionPhase(TestState state, MemoryState memoryState, ErrorState errorState)
            throws Exception {
        byte[] sharedKey = new byte[32]; // Simulate shared key
        byte[] sm4Key = Arrays.copyOf(sharedKey, 16);

        SM4Utils sm4Utils = new SM4Utils();
        byte[] encryptedData = sm4Utils.encrypt(
                state.testMessage.getBytes(StandardCharsets.UTF_8),
                sm4Key,
                state.iv);

        byte[] decryptedData = sm4Utils.decrypt(encryptedData, sm4Key, state.iv);
    }

    // // ML-KEM Tests
    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    @Fork(value = 1, warmups = 2)
    @Warmup(iterations = 1)
    @Measurement(iterations = 3)
    public void mlKemEncapsulation(TestState state, MemoryState memoryState, ErrorState errorState) {
        Pair<byte[], byte[]> serverPair = state.kemServer.encap_secret(state.kemClientPublicKey);
        byte[] kemCiphertext = serverPair.getLeft();
        byte[] kemSharedSecret = serverPair.getRight();
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    @Fork(value = 1, warmups = 2)
    @Warmup(iterations = 1)
    @Measurement(iterations = 3)
    public void mlKemDecapsulation(TestState state, MemoryState memoryState, ErrorState errorState) {
        byte[] kemSharedSecret = state.kemClient.decap_secret(state.kemCiphertext);
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    @Fork(value = 1, warmups = 2)
    @Warmup(iterations = 1)
    @Measurement(iterations = 3)
    public void mlKemFullExchange(TestState state, MemoryState memoryState, ErrorState errorState) {
        // Full ML-KEM exchange
        KeyEncapsulation kemClient = new KeyEncapsulation(state.kemName);
        byte[] clientPublicKey = kemClient.generate_keypair();

        Pair<byte[], byte[]> serverPair = state.kemServer.encap_secret(clientPublicKey);
        byte[] ciphertext = serverPair.getLeft();
        byte[] serverSharedSecret = serverPair.getRight();

        byte[] clientSharedSecret = kemClient.decap_secret(ciphertext);
    }

    // // SM2 Tests
    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    @Fork(value = 1, warmups = 2)
    @Warmup(iterations = 1)
    @Measurement(iterations = 3)
    public void sm2InitiatorGeneration(TestState state, MemoryState memoryState, ErrorState errorState) {
        SM2KeyExchange.InitiatorKeyMaterial initiatorMaterial = SM2KeyExchange.initiatorInit();
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    @Fork(value = 1, warmups = 2)
    @Warmup(iterations = 1)
    @Measurement(iterations = 3)
    public void sm2ResponderProcessing(TestState state, MemoryState memoryState, ErrorState errorState) {
        SM2KeyExchange.ResponderKeyMaterial responderMaterial = SM2KeyExchange.responderResponse(
                state.sm2InitiatorPublicKey,
                state.sm2InitiatorRa);
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    @Fork(value = 1, warmups = 2)
    @Warmup(iterations = 1)
    @Measurement(iterations = 3)
    public void sm2FullExchange(TestState state, MemoryState memoryState, ErrorState errorState) {
        // Full SM2 key exchange
        SM2KeyExchange.InitiatorKeyMaterial initiatorMaterial = SM2KeyExchange.initiatorInit();

        SM2KeyExchange.ResponderKeyMaterial responderMaterial = SM2KeyExchange.responderResponse(
                initiatorMaterial.publicKey,
                initiatorMaterial.Ra);

        byte[] finalKey = SM2KeyExchange.initiatorFinal(
                initiatorMaterial,
                responderMaterial.publicKey,
                responderMaterial.Rb);
    }

    // // 完整流程测试
    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Fork(value = 1, warmups = 2)
    @Warmup(iterations = 1)
    @Measurement(iterations = 3)
    public void fullProcessTest(TestState state, MemoryState memoryState, ErrorState errorState) throws Exception {
        // Initialization
        KeyEncapsulation kemClient = new KeyEncapsulation(state.kemName);
        byte[] kemClientPublicKey = kemClient.generate_keypair();
        SM2KeyExchange.InitiatorKeyMaterial sm2InitiatorMaterial = SM2KeyExchange.initiatorInit();
        InitiatorSession initiatorSession = new InitiatorSession(kemClient, kemClientPublicKey, sm2InitiatorMaterial);

        // Key Exchange
        Pair<byte[], byte[]> serverPair = state.kemServer.encap_secret(kemClientPublicKey);
        SM2KeyExchange.ResponderKeyMaterial sm2ResponderMaterial = SM2KeyExchange.responderResponse(
                initiatorSession.sm2Material.publicKey,
                initiatorSession.sm2Material.Ra);

        ResponderSession responderSession = new ResponderSession(
                serverPair.getRight(),
                serverPair.getLeft(),
                sm2ResponderMaterial);

        // Final key generation and encryption/decryption
        byte[] kemSharedSecretClient = initiatorSession.kemClient.decap_secret(responderSession.kemCiphertext);
        byte[] sm2SharedKeyInitiator = SM2KeyExchange.initiatorFinal(
                initiatorSession.sm2Material,
                responderSession.sm2Material.publicKey,
                responderSession.sm2Material.Rb);

        byte[] finalSharedKey = HybridKeyExchange.combineFinalKey(kemSharedSecretClient, sm2SharedKeyInitiator);
        byte[] sm4Key = Arrays.copyOf(finalSharedKey, 16);

        SM4Utils sm4Utils = new SM4Utils();
        byte[] encryptedData = sm4Utils.encrypt(
                state.testMessage.getBytes(StandardCharsets.UTF_8),
                sm4Key,
                state.iv);
        byte[] decryptedData = sm4Utils.decrypt(encryptedData, sm4Key, state.iv);
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    @Threads(10) // 可以调整并发线程数
    public void concurrentTest(TestState state, MemoryState memoryState, ErrorState errorState) throws Exception {
        // 完整流程测试
        fullProcessTest(state, memoryState, errorState);
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    @Threads(10) // 可以调整并发线程数
    public void concurrentMlKemTest(TestState state, MemoryState memoryState, ErrorState errorState) throws Exception {
        // 完整流程测试
        mlKemFullExchange(state, memoryState, errorState);
    }

}
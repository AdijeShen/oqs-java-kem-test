# 基于liboqs的java调用示例

## windows 运行

```bash
mvn clean package
java -cp "target/oqs-java-test-1.0-SNAPSHOT-jar-with-dependencies.jar;lib/windows/liboqs-java.jar" com.test.OQSTest
```

## linux 运行

```bash
mvn clean package
java -cp "target/oqs-java-test-1.0-SNAPSHOT-jar-with-dependencies.jar:lib/linux/liboqs-java.jar" com.test.OQSTest
```

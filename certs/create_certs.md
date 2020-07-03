# 自签证书生成（JDK Keytool）

### 1.服务器证书
```
keytool -genkey -alias jcbk -validity 36500 -keyalg RSA -keysize 1024 -keypass 123456 -storepass 123456 -dname "cn=localhost, ou=00, o=00, l=00, st=01, c=CN" -keystore jcbk.jks
```
### 2.客户端证书
```
keytool -genkey -alias jcbk_client -validity 7 -keyalg RSA -keysize 1024 -keypass 123456 –storetype PKCS12 -storepass 123456 -dname "cn=姓名 账号, ou=00, o=00, l=00, st=01, c=CN" -keystore jcbk_client.p12
```
### 3.导出客户端证书
```
keytool -export -alias dc_client -keystore D:/jcbk_client.p12  -storetype PKCS12 -keypass 123456  -file D:/jcbk_client.cer
```
### 4.将客户端证书导入jcbk.jks可信任库
```
keytool -import -v -file D:/jcbk_client.cer -keystore D:/jcbk.jks -storepass 123456
```

得到`jcbk_client.cer`、`jcbk.jks` 2个文件

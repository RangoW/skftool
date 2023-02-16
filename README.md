# 国密智能密码钥匙工具

## 依赖

- libgm3000.1.0.dylib 龙脉动态库
- libcrypto.1.1.dylib 国密openssl库

## 打包 dmg

利用系统工具打包出包含所有依赖库的 dmg 程序。

`macdeployqt skftool.app -dmg -verbose=3` 

若发生运行时找不到动态库的错误，查看 skftool 依赖库并确认 LC_RPATH 路径。

```shell
otool -L skftool.app/Contents/MacOS/skftool
otool -l skftool.app/Contents/MacOS/skftool | grep LC_RPATH -A2
```

再手动更改到正确的路径下，重新打包。

```shell
cd skftool.app/Contents/MacOS
install_name_tool -change libgm3000.1.0.dylib @executable_path/../Frameworks/libgm3000.1.0.dylib  skftool
```

## 个人测试使用
![image](https://user-images.githubusercontent.com/30715970/151285250-16e74993-e820-4a91-9d0b-120404c2dd56.png)
![image](https://user-images.githubusercontent.com/30715970/151285261-78f9fbaa-02f8-4583-89f4-8becc2890262.png)
![image](https://user-images.githubusercontent.com/30715970/219286610-bab20f2a-84f8-4148-b710-78fea018e5f1.png)


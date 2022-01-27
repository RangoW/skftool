# 国密智能密码钥匙工具
## 个人测试使用

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


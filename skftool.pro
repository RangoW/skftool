QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11

CONFIG+=sdk_no_version_check

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    main.cpp \
    mainwindow.cpp \
    skf_engine.cpp

HEADERS += \
    mainwindow.h \
    openssl/__DECC_INCLUDE_EPILOGUE.H \
    openssl/__DECC_INCLUDE_PROLOGUE.H \
    openssl/aes.h \
    openssl/asn1.h \
    openssl/asn1_mac.h \
    openssl/asn1t.h \
    openssl/async.h \
    openssl/bio.h \
    openssl/blowfish.h \
    openssl/bn.h \
    openssl/buffer.h \
    openssl/camellia.h \
    openssl/cast.h \
    openssl/cmac.h \
    openssl/cms.h \
    openssl/comp.h \
    openssl/conf.h \
    openssl/conf_api.h \
    openssl/crypto.h \
    openssl/ct.h \
    openssl/des.h \
    openssl/dh.h \
    openssl/dsa.h \
    openssl/dtls1.h \
    openssl/e_os2.h \
    openssl/ebcdic.h \
    openssl/ec.h \
    openssl/ecdh.h \
    openssl/ecdsa.h \
    openssl/ecies.h \
    openssl/engine.h \
    openssl/err.h \
    openssl/evp.h \
    openssl/gmapi.h \
    openssl/gmsdf.h \
    openssl/gmskf.h \
    openssl/gmtls.h \
    openssl/hkdf.h \
    openssl/hmac.h \
    openssl/idea.h \
    openssl/is_gmssl.h \
    openssl/kdf.h \
    openssl/kdf2.h \
    openssl/lhash.h \
    openssl/md2.h \
    openssl/md4.h \
    openssl/md5.h \
    openssl/mdc2.h \
    openssl/modes.h \
    openssl/obj_mac.h \
    openssl/objects.h \
    openssl/ocsp.h \
    openssl/opensslconf.h \
    openssl/opensslconf.h.in \
    openssl/opensslv.h \
    openssl/ossl_typ.h \
    openssl/otp.h \
    openssl/paillier.h \
    openssl/pem.h \
    openssl/pem2.h \
    openssl/pkcs12.h \
    openssl/pkcs7.h \
    openssl/rand.h \
    openssl/rc2.h \
    openssl/rc4.h \
    openssl/rc5.h \
    openssl/ripemd.h \
    openssl/rsa.h \
    openssl/safestack.h \
    openssl/sdf.h \
    openssl/seed.h \
    openssl/sgd.h \
    openssl/sha.h \
    openssl/skf.h \
    openssl/sm1.h \
    openssl/sm2.h \
    openssl/sm3.h \
    openssl/sm9.h \
    openssl/sms4.h \
    openssl/srp.h \
    openssl/srtp.h \
    openssl/ssf33.h \
    openssl/ssl.h \
    openssl/ssl2.h \
    openssl/ssl3.h \
    openssl/stack.h \
    openssl/symhacks.h \
    openssl/tls1.h \
    openssl/ts.h \
    openssl/txt_db.h \
    openssl/ui.h \
    openssl/whrlpool.h \
    openssl/x509.h \
    openssl/x509_vfy.h \
    openssl/x509v3.h \
    openssl/zuc.h

FORMS += \
    mainwindow.ui

LIBS += -L/usr/local/lib -lcrypto

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

DISTFILES += \
    README.md

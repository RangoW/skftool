QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    main.cpp \
    mainwindow.cpp \
    skf_engine.cpp

HEADERS += \
    mainwindow.h \
    skfapi.h

FORMS += \
    mainwindow.ui

LIBS += -L/Users/trustasia/openssl-sm/Gmssl/ -lcrypto.1.1
LIBS += -L/Users/trustasia/skftool/ -lgm3000.1.0

INCLUDEPATH += \
    /Users/trustasia/openssl-sm/GmSSL/include

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

DISTFILES += \
    README.md

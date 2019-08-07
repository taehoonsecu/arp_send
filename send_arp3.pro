TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS -= libcap

SOURCES += \
        main.cpp

HEADERS += \
    getmac.h \
    mypcap.h

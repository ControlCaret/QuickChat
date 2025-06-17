# QuickChat

Open Source E2EE Messenger using WebSocket and Ncurses

## 소개

웹소켓을 이용한 C++ 암호화 메신저 프로그램입니다. 메시지는 RSA-2048bit 알고리즘으로 암호화됩니다.

## 작동 구조

1. 클라이언트가 실행되면 자기 고유의 개인키와 공개키를 생성합니다.
2. 클라이언트가 서버에 접속하면 자신의 공개키를 서버에 전송합니다.
3. 서버는 각 클라이언트별로 공개키를 저장합니다.
4. 다른 클라이언트가 접속하면 서버는 모든 공개키를 해당 클라이언트에 전송합니다.
5. 기존 접속해있는 클라이언트에게 새로운 클라이언트의 공개키를 전송합니다.
6. 클라이언트에서 메시지를 입력하고 전송합니다.
7. 클라이언트는 메시지를 모든 사용자 각각의 공개키로 암호화한 뒤 서버에 전송합니다.
8. 서버는 각 클라이언트에게 자신의 공개키로 암호화된 메시지를 전송합니다.
9. 암호화된 메시지를 받은 클라이언트는 자신의 개인키로 메시지를 복호화한 뒤 출력합니다.
10. 한 클라이언트가 접속을 종료하면 서버와 다른 클라이언트는 해당 클라이언트의 키를 삭제합니다.

## 의존성

GCC
```console
apt install gcc
```

CMAKE
```console
apt install cmake
```

OpenSSL
```console
apt install libssl-dev
```

Ncurses
```console
apt install libncurses5-dev libncursesw5-dev
```

## 컴파일

TBD

## 실행

### 서버
```console
./build_server/QC_server
```

### 클라이언트
```console
./build_client/executable/QuickChat 127.0.0.1 24680
```

## 스펙

* C++ Class WebSocket
* OpenSSL 라이브러리 이용 RSA-2048bit 암호화 복호화 알고리즘
* Ncurses 기반 TUI
* 클라이언트 실행마다 바뀌는 암호화 키

## 알려진 문제

* 첫 실행 시 작동 불안정
* 한글 및 일부 유니코드 입력 불가
* 한 줄을 넘어가는 긴 문장 입력시 UI 깨짐
* 가끔 깨져서 전송되는 메시지

## 참고

#### C++ uses OpenSSL for RSA encryption and decryption
https://www.programmersought.com/article/37955188510/

#### Sloan Kelly's "Starter UDP Server and Client in C++"
https://youtube.com/c/sloankelly

https://bitbucket.org/sloankelly/youtube-source-repository/src/master/cpp/networking/

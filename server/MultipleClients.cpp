#include "MultipleClients.h"
#include <arpa/inet.h>
#include <iostream>
#include <netdb.h>
#include <poll.h>
#include <sstream>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include "../utils/utility.h"

Server::Server() { this->initServer(); }

Server::~Server() {
    std::cout << "Server Closed" << std::endl;
    FD_CLR(_listening, &_master);
    close(_listening);
}

template<typename T>
void Server::updateDictionary(int key, T value, std::map<int, T> *dictionary) {
    typename std::map<int, T>::iterator it = dictionary->find(key);
    
    if (it != dictionary->end()) {
        it->second = value;
    } else {
        dictionary->insert(std::make_pair(key, value));
    }
}

bool Server::userFirstMessage(int k) {
    std::map<int, bool>::iterator it = _userFirstMessage.find(k);
    if (it == _userFirstMessage.end()) {
        return true;
    } else {
        return it->second;
    }
}

void Server::getPK(int key, std::string message) {
    bool missingKey = Utils::findWord(message, "-----BEGIN RSA PUBLIC KEY-----");
    
    if (!missingKey) {
        std::cout << "Key socket #" << std::to_string(key) << message << std::endl;
        this->updateDictionary(key, message, &_userToPK);
    } else {
        std::string empty_key{"-----KEY NOT FOUND-----"};
        this->updateDictionary(key, empty_key, &_userToPK);
    }
}

std::string Server::getPK(int key) {
    return _userToPK.at(key);
}

void Server::eraseMaps(int sock) {
    _loggedUsers.erase(sock);
    _userFirstMessage.erase(sock);
    _userToPK.erase(sock);
}

int Server::initServer() {
    this->_listening = socket(AF_INET, SOCK_STREAM, 0);
    
    if (_listening == -1) {
        std::cerr << "Can't create a socket.";
        return -1;
    }

    sockaddr_in hint;
    hint.sin_family = AF_INET;
    hint.sin_port = htons(24680);
    inet_pton(AF_INET, "0.0.0.0", &hint.sin_addr);
    
    if (bind(_listening, (sockaddr *)&hint, sizeof(hint)) == -1) {
        std::cerr << "Can't bind to IP/Port.";
        return -2;
    }
    if (listen(_listening, SOMAXCONN) == -1) {
        std::cerr << "Can't listen.";
        return -3;
    }
    
    FD_ZERO(&_master);
    FD_SET(_listening, &_master);
    return( 0 );
}

void Server::runServer() {
    while (true) {
        auto copy = _master;
        int socketCount = select(FD_SETSIZE, &copy, nullptr, nullptr, nullptr);
        
        for (int sock = 0; sock <= FD_SETSIZE - 1; ++sock) {
            if (!FD_ISSET(sock, &copy)) continue;
            sockaddr_in req_addr;
            
            if (sock == _listening) {
                auto client = accept(_listening, nullptr, nullptr);
                
                FD_SET(client, &_master);
                
                std::set<int> loggedUsersTemp = _loggedUsers;
                _loggedUsers.insert(client);
                std::string all_users;
                for (int user : _loggedUsers) {
                    all_users += std::to_string(user) + ";";
                }    
                
                for (int user : _loggedUsers) {
                    if (user != client) {
                        std::string temp_pk = _userToPK.at(user);
                        all_users += "," + std::to_string(user) + ":" + temp_pk + ",";
                    }
                }
                
                std::cout << all_users << std::endl;  
                
                send(client, all_users.c_str(), all_users.size() + 1, 0);
                
                for (int outSock = 0; outSock <= FD_SETSIZE - 1; ++outSock) {
                    if (outSock != _listening && outSock != sock) {
                        std::ostringstream ss;
                        ss << "USER #" << client << " has joined.\r\n";
                        std::string strOut = ss.str();
                        send(outSock, strOut.c_str(), strOut.size() + 1, 0);
                    }
                }
            } else {
                char buf[4096];
                memset(buf, 0, 4096);
                
                int bytesIn = recv(sock, buf, 4096, 0);
                if (bytesIn <= 0) {
                    close(sock);
                    FD_CLR(sock, &_master);
                    
                    for (int outSock = 0; outSock <= FD_SETSIZE - 1; ++outSock) {
                        if (outSock != _listening && outSock != sock) {
                            std::ostringstream ss;
                            ss << "USER #" << sock << " has left.";
                            
                            this->eraseMaps(sock);
                            
                            std::string strOut = ss.str();
                            send(outSock, strOut.c_str(), strOut.size() + 1, 0);
                        }
                    }
                    
                } else {
                    std::ostringstream ss;
                    ss << buf;
                    
                    std::string getLength = ss.str(); 
                    int msgLength;
                    std::string temp_string, removeHeader;
                    
                    std::replace(getLength.begin(), getLength.end(), '\n', ' ');
                    
                    std::istringstream sline(getLength);
                    sline >> temp_string >> msgLength;
                    
                    removeHeader = "-----BEGIN\n" + std::to_string(msgLength) + "\nEND-----";
                    
                    std::string strMessage;
                    char *strbuf = const_cast<char *>(buf);
                    for (int i = 0; i < msgLength + removeHeader.length(); i++) {
                        strMessage.push_back(strbuf[i]);
                    }
                    
                    size_t p = -1;
                    std::string tempWord = removeHeader + "";
                    while ((p = strMessage.find(removeHeader)) != std::string::npos) {
                        strMessage.replace(p, tempWord.length(), "");
                    }
                    
                    std::vector<std::string> messages = Utils::split(strMessage, "-----NEWMESSAGE-----");
                    
                    std::string user_header = "USER #" + std::to_string(sock) + ": ";
                    
                    std::map<int, char *> userToMessage;
                    for (std::string msg : messages) {
                        int usr;
                        std::string tempString, getUser;
                        getUser = msg;
                        
                        std::replace(getUser.begin(), getUser.end(), '_', ' ');
                        std::istringstream sline(getUser);
                        sline >> usr;
                        
                        size_t p = -1;
                        std::string tempWord = std::to_string(usr) + "_";
                        while ((p = msg.find(std::to_string(usr) + "_")) != std::string::npos) {
                            msg.replace(p, tempWord.length(), "");
                        }
                        
                        char *tempbuf = new char[256 + user_header.length()];
                        int j = 0;
                        for (int i = 0; i < 256 + user_header.length(); i++) {
                            if (i < user_header.length()) {
                                tempbuf[i] = user_header[i];
                            } else {
                                tempbuf[i] = msg[j];
                                j++;
                            }
                        }
                        userToMessage.insert(std::make_pair(usr, tempbuf));
                    }
                    
                    std::string pK = "";
                    if (this->userFirstMessage(sock)) {
                        this->updateDictionary(sock, false, &this->_userFirstMessage);
                        this->getPK(sock, ss.str());
                        pK = this->getPK(sock);
                    }
                    
                    for (int outSock = 0; outSock <= FD_SETSIZE - 1; ++outSock) {
                        if (outSock != _listening && outSock != sock) {
                            if (pK == "") {
                                std::map<int, char*>::iterator it = userToMessage.find(outSock);
                                if (it != userToMessage.end()) {
                                    send(outSock, it->second, 256 + user_header.length() + 1, 0);
                                    delete it->second;
                                } else {
                                    send(outSock, ss.str().c_str(), ss.str().length() + 1, 0);
                                }
                            }
                            else {
                                std::string header_pk = user_header + pK;
                                send(outSock, header_pk.c_str(), header_pk.size() + 1, 0);
                            }
                        }
                    }
                }
            }
        }
    }
}

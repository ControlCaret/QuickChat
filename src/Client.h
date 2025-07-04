#ifndef CLIENT_H
#define CLIENT_H
#include <string>
#include <mutex>
#include <curses.h>
#include <vector>
#include <map>
#include "utility.h"
#include "RSAEncrypt.h"

class ArrivingMessages {
public:
    RSAEncrypt rsa = RSAEncrypt(); 

    int getSize();
    void pushBack(std::string response);
    void setMessage(std::string message); 
    std::vector<std::string> getResponses();
    std::string getMessage(); 
    void setUserData(std::string users);
    void appendUser(int user); 
    void removeUser(std::string message); 
    std::vector<int> getUsers(); 
    bool messageIsEmpty(); 
    void clearMessage(); 
    void updatePK(int key, std::string pK);
    std::map<int, std::string> getPKeys();
    std::string sendPublicKey();
    void decryptMessage(int index, int user, std::string encryptedMsg); 
    
private:
    std::vector<std::string> _responses;
    std::string _message; 
    std::vector<int> _users;
    std::map<int, std::string> _userToPK;  
    std::mutex _mutex;
};

class Client {
public:
    Client(char *&ipAddress, char *&portNum);
    ~Client(); 
    int createConnection();
    void runClient();
    void runSendMessage(); 

    void setMessage(std::string message); 
    
    std::vector<std::string> getResponses(); 
    std::vector<int> getUsers(); 
    void clearMessage(); 
    void pushBack(std::string message);
    void appendUser(int user);  
    std::string sendPublicKey(); 
    std::map<int, std::string> getPKeys(); 
    
    void updatePK(int user, std::string pK);
    bool addPK(std::string message);
    int addUser(std::string message); 
    void decryptMessage(std::string message, int index); 
    void processMessages(); 
    bool generateKeys(); 
    
    int getCountFM();
    void addCountFM(); 
    
    private:
    char *&_ipAddress;
    char *&_portNum;
    int _sockFD;
    int _connectR;
    int _firstMessages; 
    ArrivingMessages _arrivingMessages; 
    std::vector<std::string> _prevResponses; 
    std::mutex *_mtx;
};

#endif

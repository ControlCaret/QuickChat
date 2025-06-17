#include "NcursesDisplay.h"

int main(int argc, char *argv[]) {
    auto &ipAddress = argv[1];
    auto &portNum   = argv[2];
    NcursesDisplay::Display(ipAddress, portNum); 
}

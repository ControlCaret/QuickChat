#ifndef TIMESTAMP_DISPLAY_H
#define TIMESTAMP_DISPLAY_H
#include <string>

namespace Utils {
    inline std::string timeStampToHReadble(const time_t rawtime) {
        struct tm *dt;
        char buffer[30];
        dt = localtime(&rawtime);
        strftime(buffer, sizeof(buffer), "%H:%M:%S", dt);
        return std::string(buffer);
    }
}
#endif

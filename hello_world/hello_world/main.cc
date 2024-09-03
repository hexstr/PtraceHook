#include <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <iostream>

#include "crc32.hh"

extern "C" {
[[gnu::visibility("default")]] void test(int i) {
    if (i < 5) {
        printf("[%d] [%d] Error answer.\n", getpid(), gettid());
    }
    else {
        std::cout << "flag{abcd1234}" << std::endl;
    }
}
}
using ptrace_proc_t = void (*)(intptr_t);
static ptrace_proc_t ptrace_proc = nullptr;
static int64_t orig_crc = Utility::Crc32Compute((const void*)test, 0x74);

int main(int argc, char** argv) {
    std::cout << "Hello world~" << std::endl;
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        strcat(cwd, "/libfuck_the_world.so");
    }
    else {
        perror("getcwd() error");
        return 1;
    }

    while (true) {
        static void* handle = nullptr;
        static bool first_init = true;
        if (first_init == false && handle == nullptr) {
            handle = dlopen(cwd, RTLD_NOW);
            if (handle == nullptr) {
                std::cout << dlerror() << std::endl;
            }

            if ((ptrace_proc = reinterpret_cast<ptrace_proc_t>(dlsym(handle, "ptrace_proc")))) {
                ptrace_proc(reinterpret_cast<intptr_t>(test));
            }
            else {
                std::cout << "ptrace_proc not found." << std::endl;
            }
        }
        first_init = false;
        int64_t crc = Utility::Crc32Compute((const void*)test, 0x74);
        if (crc != orig_crc) {
            std::cout << "crc check failed. " << std::hex << crc << std::endl;
            unsigned char* ptr = reinterpret_cast<unsigned char*>(test);
            printf("%02X %02X %02X %02X\n", ptr[0], ptr[1], ptr[2], ptr[3]);
            ptr += 4;
            printf("%02X %02X %02X %02X\n", ptr[0], ptr[1], ptr[2], ptr[3]);
        }
        else {
            test(argc);
        }
        sleep(2);
    }
}
#include <asm/ptrace.h>
#include <elf.h>
#include <stdint.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <string>

struct user_regs_64 {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

union user_regs_t {
    // struct user_regs_32 regs32;
    struct user_regs_64 regs64;
};

#define logger(str, ...) printf(str "\n", ##__VA_ARGS__)

using ori_test_t = void (*)(int);
static ori_test_t ori_test = nullptr;
static intptr_t test_addr = 0;
void new_test(int i) {
    printf("[new_test] %d -> 234\n", i);
    int32_t opcode = *reinterpret_cast<int32_t*>(test_addr);
    if (opcode != 0xD10083FF) {
        logger("opcode [%X] not matched.", opcode);
        return;
    }
    asm volatile("sub sp, sp, #0x20");
    ori_test(234);
}

enum target_hw_bp_type {
    hw_write = 0,  /* Common  HW watchpoint */
    hw_read = 1,   /* Read    HW watchpoint */
    hw_access = 2, /* Access  HW watchpoint */
    hw_execute = 3 /* Execute HW breakpoint */
};

unsigned int aarch64_point_encode_ctrl_reg(enum target_hw_bp_type type, int len) {
    unsigned int ctrl, ttype;

    /* type */
    switch (type) {
        case hw_write:
            ttype = 2;
            break;
        case hw_read:
            ttype = 1;
            break;
        case hw_access:
            ttype = 3;
            break;
        case hw_execute:
            ttype = 0;
            break;
        default:
            logger("Unrecognized breakpoint/watchpoint type");
    }

    /* type */
    ctrl = ttype << 3;
    /* length bitmask */
    ctrl |= ((1 << len) - 1) << 5;
    /* enabled at el0 */
    ctrl |= (2 << 1) | 1;

    return ctrl;
}

class ChildProc {
public:
    explicit ChildProc(pid_t pid) : pid_(pid){};

    bool Attach();
    bool Continue();
    bool IsSupportHWBP();
    bool SetDebugRegs(uint64_t addr, uint32_t ctrl);

    user_pt_regs ReadRegisters();
    bool WriteRegisters(user_pt_regs& args);

private:
    pid_t pid_;
};

bool ChildProc::Attach() {
    if (ptrace(PTRACE_ATTACH, pid_, nullptr, nullptr) == -1) {
        logger("[Attach] Error: %s", strerror(errno));
        return false;
    }
    return true;
}

bool ChildProc::Continue() {
    if (ptrace(PTRACE_CONT, pid_, nullptr, nullptr) != 0) {
        logger("ptrace continue failed: %s", strerror(errno));
        return false;
    }
    return true;
}

bool ChildProc::IsSupportHWBP() {
    user_hwdebug_state dreg_state;
    iovec iov;
    iov.iov_base = &dreg_state;
    iov.iov_len = sizeof(dreg_state);
    long result = ptrace(PTRACE_GETREGSET, pid_, NT_ARM_HW_BREAK, &iov);
    if (result == -1) {
        logger("[%d] Hardware support missing: %s", pid_, strerror(errno));
        return false;
    }
    int hwbp_regs_num = (dreg_state.dbg_info & 0xff);
    logger("hwbp_regs_num: %d", hwbp_regs_num);
    return hwbp_regs_num != 0 ? true : false;
}

bool ChildProc::SetDebugRegs(uint64_t addr, uint32_t ctrl) {
    logger("[SetDebugRegs] %lX", addr);

    user_hwdebug_state dreg_state{};
    dreg_state.dbg_regs[0].addr = addr;
    dreg_state.dbg_regs[0].ctrl = ctrl;

    iovec iov;
    iov.iov_base = &dreg_state;
    iov.iov_len = offsetof(user_hwdebug_state, dbg_regs) + sizeof(dreg_state.dbg_regs[0]);

    if (ptrace(PTRACE_SETREGSET, pid_, NT_ARM_HW_BREAK, &iov) != 0) {
        logger("[SetDebugRegs] Error: %s", strerror(errno));
        return false;
    }
    return true;
}

user_pt_regs ChildProc::ReadRegisters() {
    user_pt_regs regs;
    const struct iovec pt_iov = {
        .iov_base = &regs,
        .iov_len = sizeof(regs),
    };

    if (ptrace(PTRACE_GETREGSET, pid_, NT_PRSTATUS, &pt_iov) == -1) {
        logger("[ReadRegister] PTRACE_GETREGSET Error: %s", strerror(errno));
        return {};
    }

    int regs_len = pt_iov.iov_len;
    if (regs_len == sizeof(user_pt_regs)) {
        return regs;
    }

    logger("Unknown registers structure size: '%zd'", pt_iov.iov_len);
    return {};
}

bool ChildProc::WriteRegisters(user_pt_regs& regs) {
    const struct iovec pt_iov = {
        .iov_base = &regs,
        .iov_len = sizeof(regs),
    };

    if (ptrace(PTRACE_SETREGSET, pid_, NT_PRSTATUS, &pt_iov) == -1) {
        logger("[WriteRegister] PTRACE_SETREGSET Error: %s", strerror(errno));
        return {};
    }

    int regs_len = pt_iov.iov_len;
    if (regs_len == sizeof(user_pt_regs)) {
        return true;
    }

    logger("Unknown registers structure size: '%zd'", pt_iov.iov_len);
    return false;
}

extern "C" {
[[gnu::visibility("default")]] void ptrace_proc(intptr_t hook_addr) {
    if (hook_addr) {
        test_addr = hook_addr;
        ori_test = reinterpret_cast<void (*)(int)>(hook_addr + 4);
        logger("new_test: %p ori_test: %p", new_test, ori_test);

        pid_t parent_id = getpid();
        pid_t child = fork();
        if (child == -1) {
            logger("error: %s", strerror(errno));
        }
        else if (child == 0) {
            // child process
            logger("[child] pid: %d <- %d", getpid(), parent_id);

            ChildProc proc(parent_id);

            if (proc.Attach() == false) {
                exit(0);
            }

            int status;
            int wpid = waitpid(parent_id, &status, __WALL);
            if (wpid != parent_id) {
                logger("waitpid failed: %s", strerror(errno));
                exit(0);
            }
            if (!WIFSTOPPED(status)) {
                logger("child did not stop");
                exit(0);
            }
            if (WSTOPSIG(status) != SIGSTOP) {
                logger("child did not stop with SIGSTOP");
                exit(0);
            }

            if (proc.IsSupportHWBP() == false) {
                exit(0);
            }

            if (proc.SetDebugRegs(hook_addr, aarch64_point_encode_ctrl_reg(hw_execute, 4)) == false) {
                exit(0);
            }

            if (proc.Continue() == false) {
                exit(0);
            }

            ptrace(PTRACE_SETOPTIONS, parent_id, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL);

            while ((wpid = wait(&status), WIFEXITED(status) == 0)) {
                if (wpid != parent_id) {
                    logger("waitpid() failed: %s\n", strerror(errno));
                    exit(0);
                }

                logger("========= HWBP Triggered =========");

                if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
                    user_pt_regs regs = proc.ReadRegisters();
                    logger("[ReadRegisters] pc: %llX x0: %llX", regs.pc, regs.regs[0]);

                    regs.pc = reinterpret_cast<uint64_t>(new_test);
                    const struct iovec pt_iov = {
                        .iov_base = &regs,
                        .iov_len = sizeof(regs),
                    };

                    if (proc.WriteRegisters(regs) == false) {
                        exit(0);
                    }
                    logger("[WriteRegisters]");

                    regs = proc.ReadRegisters();
                    logger("[ReadRegisters] pc: %llX x0: %llX", regs.pc, regs.regs[0]);

                    proc.Continue();
                    logger("========= HWBP Resumed =========");
                }
                else {
                    logger("ERROR: WIFSTOPPED: %d WSTOPSIG: %d", WIFSTOPPED(status), WSTOPSIG(status));
                }
            }
        }
        else {
            // parent process
            logger("[parent] pid: %d -> %d", parent_id, child);
        }
    }
    else {
        logger("No test_addr");
        return;
    }
}
}
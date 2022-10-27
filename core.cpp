#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/ptrace.h>

#include "core.h"
#include "logger.h"
#include "testlib.h"

extern int errno;

// output result
static void output_result() {
    FILE *result_file = fopen(PROBLEM::result_file.c_str(), "w");
    switch (PROBLEM::result) {
        case 1:
            PROBLEM::status = "Compile Error";
            break;
        case 2:
            PROBLEM::status = "Time Limit Exceeded";
            break;
        case 3:
            PROBLEM::status = "Memory Limit Exceeded";
            break;
        case 4:
            PROBLEM::status = "Output Limit Exceeded";
            break;
        case 5:
            PROBLEM::status = "Runtime Error";
            break;
        case 6:
            PROBLEM::status = "Wrong Answer";
            break;
        case 7:
            PROBLEM::status = "Accepted";
            break;
        case 8:
            PROBLEM::status = "Presentation Error";
            break;
        default:
            PROBLEM::status = "System Error";
            break;
    }
    fprintf(result_file, "%d\n", PROBLEM::result);
    fprintf(result_file, "%d\n", PROBLEM::time_usage);
    fprintf(result_file, "%d\n", PROBLEM::memory_usage);
    fprintf(result_file, "%s\n", PROBLEM::extra_message.c_str());

    FM_LOG_TRACE("The final result is %s %d %d %s", PROBLEM::status.c_str(), PROBLEM::time_usage, PROBLEM::memory_usage,
                 PROBLEM::extra_message.c_str());
}

// parse arguments
static void parse_arguments(int argc, char *argv[]) {
    int opt;
    extern char *optarg;

    while ((opt = getopt(argc, argv, "l:t:m:d:s")) != -1) {
        switch (opt) {
            case 'l':
                PROBLEM::lang = atoi(optarg);
                break;
            case 't':
                PROBLEM::time_limit = atoi(optarg);
                break;
            case 'm':
                PROBLEM::memory_limit = atoi(optarg);
                break;
            case 's':
                PROBLEM::spj = true;
                break;
            case 'd':
                PROBLEM::run_dir = optarg;
                break;
            default:
                FM_LOG_WARNING("Unknown option provided: -%c %s", opt, optarg);
                exit(JUDGE_CONF::EXIT_BAD_PARAM);
        }
    }


    FM_LOG_DEBUG("PROBLEM::run_dir = %s\n", PROBLEM::run_dir.c_str());

    PROBLEM::exec_file = PROBLEM::run_dir + "/Main";
    PROBLEM::input_file = PROBLEM::run_dir + "/in.in";
    PROBLEM::output_file = PROBLEM::run_dir + "/out.out";
    PROBLEM::exec_output = PROBLEM::run_dir + "/out.txt";
    PROBLEM::result_file = PROBLEM::run_dir + "/result.txt";

    if (PROBLEM::lang == JUDGE_CONF::LANG_JAVA) {
        // Java: relax time&memory limit
        PROBLEM::time_limit *= JUDGE_CONF::JAVA_TIME_FACTOR;
        PROBLEM::memory_limit *= JUDGE_CONF::JAVA_MEM_FACTOR;
    }

    if (PROBLEM::spj) {
        PROBLEM::spj_lang = JUDGE_CONF::LANG_CPP;
        PROBLEM::spj_exec_file = PROBLEM::run_dir + "/SpecialJudge";
        PROBLEM::spj_output_file = PROBLEM::run_dir + "/spj_output.txt";
    }

    FM_LOG_DEBUG("PROBLEM::input_file = %s\n", PROBLEM::input_file.c_str());
    FM_LOG_DEBUG("PROBLEM::output_file = %s\n", PROBLEM::output_file.c_str());
    FM_LOG_DEBUG("PROBLEM::exec_output = %s\n", PROBLEM::exec_output.c_str());
    FM_LOG_DEBUG("PROBLEM::result_file = %s\n", PROBLEM::result_file.c_str());
    FM_LOG_DEBUG("PROBLEM::spj_output_file = %s\n", PROBLEM::spj_output_file.c_str());
    
}

// timeout callback
static void timeout(int signal) {
    //超时的回调函数
    if (signal == SIGALRM) {
        exit(JUDGE_CONF::EXIT_TIMEOUT);
    }
}

// set time limit
/**
 * struct itimerval{
 *      struct timeval it_interval;   时间间隔
 *      struct timeval it_value;   第一次到点的时间
 * };
 * int setitimer(int which, const struct itimerval *new_value,struct itimerval *old_value); //设置定时器
 * @param which  指定定时方式，ITIMER_REAL 是Linux中的定时器，以系统真实时间来计算，发送SIGALRM信号
 * @param milliseconds
 * @return 返回值：成功: 0;失败: -1,设置 errno
 */
static int malarm(int which, int milliseconds) {
    struct itimerval t;
    t.it_value.tv_sec = milliseconds / 1000;
    t.it_value.tv_usec = milliseconds % 1000 * 1000; //microsecond
    t.it_interval.tv_sec = 0;
    t.it_interval.tv_usec = 0;
    return setitimer(which, &t, NULL);
}

// IO redirect
static void io_redirect() {
    FM_LOG_TRACE("Start to redirect the IO.");
    stdin = freopen(PROBLEM::input_file.c_str(), "r", stdin);
    stdout = freopen(PROBLEM::exec_output.c_str(), "w", stdout);

    if (stdin == NULL || stdout == NULL) {
        FM_LOG_WARNING("It occur a error when freopen: stdin(%p) stdout(%p)", stdin, stdout);
        exit(JUDGE_CONF::EXIT_PRE_JUDGE);
    }
    FM_LOG_TRACE("redirect io is OK.");
}

/*
 * security control
 * chroot - Restricts the program can only operate in a certain directory, cannot affect the outside
 * setuid - Make it only have the minimum system permission of `nobody`
 */
static void security_control() {
    //getpwnam()用来逐一搜索参数name 指定的账号名称, 找到时便将该用户的数据以passwd 结构返回。passwd 结构请参考getpwent()
    //返回 passwd 结构数据, 如果返回NULL 则表示已无数据, 或有错误发生.
    struct passwd *nobody = getpwnam("nobody");
    if (nobody == NULL) {
        FM_LOG_WARNING("Well, where is nobody? I cannot live without him. %d: %s", errno, strerror(errno));
        exit(JUDGE_CONF::EXIT_SET_SECURITY);
    }

    // chdir
    /**
     * chdir函数用于改变当前工作目录。调用参数是指向目录的指针，调用进程需要有搜索整个目录的权限。
     * 每个进程都具有一个当前工作目录。在解析相对目录引用时，该目录是搜索路径的开始之处。
     * 如果调用进程更改了目录，则它只对该进程有效，而不能影响调用它的那个进程。在退出程序时，shell还会返回开始时的那个工作目录。
     */
    if (EXIT_SUCCESS != chdir(PROBLEM::run_dir.c_str())) {
        FM_LOG_WARNING("chdir(%s) failed, %d: %s", PROBLEM::run_dir.c_str(), errno, strerror(errno));
        exit(JUDGE_CONF::EXIT_SET_SECURITY);
    }

    /**
     * char *getcwd(char *buf,size_t size);
     * getcwd()会将当前⼯作⽬录的绝对路径复制到参数buffer所指的内存空间中,参数size为buf的空间⼤⼩
     */
    char cwd[1024], *tmp = getcwd(cwd, 1024);
    if (tmp == NULL) {
        FM_LOG_WARNING("Oh, where i am now? I cannot getcwd. %d: %s", errno, strerror(errno));
        exit(JUDGE_CONF::EXIT_SET_SECURITY);
    }

    // chroot
    // JVM cannot run with chroot/setuid
    if (PROBLEM::lang != JUDGE_CONF::LANG_JAVA) {
        //chroot，即 change root directory (更改 root 目录)。
        // 在 linux 系统中，系统默认的目录结构都是以 /，即以根 (root) 开始的。而在使用 chroot 之后，系统的目录结构将以指定的位置作为 / 位置。
        if (EXIT_SUCCESS != chroot(cwd)) {
            FM_LOG_WARNING("chroot(%s) failed. %d: %s", cwd, errno, strerror(errno));
            exit(JUDGE_CONF::EXIT_SET_SECURITY);
        }
        // setuid
        //setuid()用来重新设置执行目前进程的用户识别码。不过，要让此函数有作用，其有效的用户识别码必须为0(root)。
        // 在Linux下，当root 使用setuid()来变换成其他用户识别码时，root权限会被抛弃，完全转换成该用户身份，
        // 也就是说，该进程往后将不再具有可setuid()的权利，如果只是向暂时抛弃root 权限，稍后想重新取回权限，则必须使用seteuid()。
        if (EXIT_SUCCESS != setuid(nobody->pw_uid)) {
            FM_LOG_WARNING("setuid(%d) failed. %d: %s", nobody->pw_uid, errno, strerror(errno));
            exit(JUDGE_CONF::EXIT_SET_SECURITY);
        }
    }

}

// security control for spj
static void security_control_spj() {
    struct passwd *nobody = getpwnam("nobody");
    if (nobody == NULL) {
        FM_LOG_WARNING("Well, where is nobody? I cannot live without him. %d: %s", errno, strerror(errno));
        exit(JUDGE_CONF::EXIT_SET_SECURITY);
    }

    if (EXIT_SUCCESS != chdir(PROBLEM::run_dir.c_str())) {
        FM_LOG_WARNING("chdir(%s) failed, %d: %s", PROBLEM::run_dir.c_str(), errno, strerror(errno));
        exit(JUDGE_CONF::EXIT_SET_SECURITY);
    }

    char cwd[1024], *tmp = getcwd(cwd, 1024);
    if (tmp == NULL) {
        FM_LOG_WARNING("Oh, where i am now? I cannot getcwd. %d: %s", errno, strerror(errno));
        exit(JUDGE_CONF::EXIT_SET_SECURITY);
    }

    //if (PROBLEM::spj_lang != JUDGE_CONF::LANG_JAVA) {
    //    if (EXIT_SUCCESS != chroot(cwd)) {
    //        FM_LOG_WARNING("chroot(%s) failed. %d: %s", cwd, errno, strerror(errno));
    //        exit(JUDGE_CONF::EXIT_SET_SECURITY);
    //    }
    //}

    //if (EXIT_SUCCESS != setuid(nobody->pw_uid)) {
    //    FM_LOG_WARNING("setuid(%d) failed. %d: %s", nobody->pw_uid, errno, strerror(errno));
    //    exit(JUDGE_CONF::EXIT_SET_SECURITY);
    //}
}

/**
 * program runtime limit
 * cpu-time/stack-size/output-size
 * getrlimit()和setrlimit()系统调用允许一个进程读取和修改自己的资源限制
 */
static void set_limit() {
    /**
      * 每个进程在运行时系统不会无限制的允许单个进程不断的消耗资源，因此都会设置资源限制。
      * Linux系统中使用resource limit来表示，每个进程都可以设置不同的资源限制，
      * 当前进程和其以后fork的子进程会遵循此限制，而其他进程不受当前进程条件的影响。
      * struct rlimit {
　    *  　rlim_t rlim_cur;
　　  *    rlim_t rlim_max;
     *  };
     */
    rlimit lim;

    // cpu-time limit
    lim.rlim_max = (PROBLEM::time_limit - PROBLEM::time_usage + 999) / 1000 + 1;
    lim.rlim_cur = lim.rlim_max;
    if (setrlimit(RLIMIT_CPU, &lim) < 0) {
        FM_LOG_WARNING("error setrlimit for RLIMIT_CPU");
        exit(JUDGE_CONF::EXIT_SET_LIMIT);
    }

    // cannot set memory-limit here because of the linux's Memory Allocation Mechanism
    // must accumulation in running


    // stack-size limit
    // RLIMIT_STACK //最大的进程堆栈，以字节为单位。
    // 读取最大进程堆栈到lim中
    getrlimit(RLIMIT_STACK, &lim);

    int rlim = JUDGE_CONF::STACK_SIZE_LIMIT * JUDGE_CONF::KILO;
    //如果题目设置的堆栈内存大于服务器最大可用大小
    if (lim.rlim_max <= rlim) {
        FM_LOG_WARNING("cannot set stack size to higher(%d <= %d)", lim.rlim_max, rlim);
    } else {
        lim.rlim_max = rlim;
        lim.rlim_cur = rlim;
        if (setrlimit(RLIMIT_STACK, &lim) < 0) {
            FM_LOG_WARNING("error setrlimit for RLIMIT_STACK");
            exit(JUDGE_CONF::EXIT_SET_LIMIT);
        }
    }

    // close log to avoid OLE
    log_close();

    // output-size limit
    lim.rlim_max = PROBLEM::output_limit * JUDGE_CONF::KILO;
    lim.rlim_cur = lim.rlim_max;
    if (setrlimit(RLIMIT_FSIZE, &lim) < 0) {
        perror("setrlimit RLIMIT_FSIZE failed\n");
        exit(JUDGE_CONF::EXIT_SET_LIMIT);
    }
}

#include "rf_table.h"

static bool in_syscall = true;

static bool is_valid_syscall(int lang, int syscall_id, pid_t child, user_regs_struct regs) {
    in_syscall = !in_syscall;
    if (RF_table[syscall_id] == 0) {
        // =0: valid
        long addr;
        if (syscall_id == SYS_open) {
#if __WORDSIZE == 32
            addr = regs.ebx;
#else
            addr = regs.rdi;
#endif
#define LONGSIZE sizeof(long)
            union u {
                unsigned long val;
                char chars[LONGSIZE];
            } data;
            unsigned long i = 0, j = 0, k = 0;
            char filename[300];
            while (true) {
                data.val = ptrace(PTRACE_PEEKDATA, child, addr + i, NULL);
                i += LONGSIZE;
                for (j = 0; j < LONGSIZE && data.chars[j] > 0 && k < 256; j++) {
                    filename[k++] = data.chars[j];
                }
                if (j < LONGSIZE && data.chars[j] == 0)
                    break;
            }
            filename[k] = 0;
            //FM_LOG_TRACE("syscall open: filename: %s", filename);
            if (strstr(filename, "..") != NULL) {
                return false;
            }
            if (strstr(filename, "/proc/") == filename) {
                return true;
            }
            if (strstr(filename, "/dev/tty") == filename) {
                PROBLEM::result = JUDGE_CONF::RE;
                exit(JUDGE_CONF::EXIT_OK);
            }
        }
        return false;
    } else if (RF_table[syscall_id] > 0) {
        // >0 && out_syscall: rest--
        if (in_syscall == false)
            RF_table[syscall_id]--;
    } else {
        // <0
        ;
    }
    return true;
}

// begin judge
static void judge() {
    struct rusage rused;
    pid_t executive = fork();
    if (executive < 0) {
        exit(JUDGE_CONF::EXIT_PRE_JUDGE);
    } else if (executive == 0) {
        // child: user-program
        FM_LOG_TRACE("Start Judging.");

        // prepare
        // 获取到了stdin和stdout的文件流
        io_redirect();
        security_control();

        int real_time_limit = PROBLEM::time_limit;
        if (EXIT_SUCCESS != malarm(ITIMER_REAL, real_time_limit)) {
            exit(JUDGE_CONF::EXIT_PRE_JUDGE);
        }
        //题目内存等限制的设置
        set_limit();

        /* ptrace() 是一个由 Linux 内核提供的系统调用，
           允许一个用户态进程检查、修改另一个进程的内存和寄存器，通常用在类似 gdb、strace 的调试器中，用来实现断点调试、系统调用的跟踪。
           第一个参数：enum __ptrace_request request：指示了ptrace要执行的命令。
           第二个参数：pid_t pid: 指示ptrace要跟踪的进程。
           第三个参数：void *addr: 指示要监控的内存地址。
           第四个参数：void *data: 存放读取出的或者要写入的数据。
         */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            exit(JUDGE_CONF::EXIT_PRE_JUDGE_PTRACE);
        }

        /// running
        /// 我们用fork函数创建新进程后，经常会在新进程中调用exec族函数去执行新的程序；当该进程调用exec族函数时，该进程被替代为新程序，因为exec族函数并不创建新进程，所以前后进程ID并未改变
        if (PROBLEM::lang != JUDGE_CONF::LANG_JAVA) {
            execl("./Main", "Main", NULL);
        } else {
            execlp("java", "java", "Main", NULL);
        }

        exit(JUDGE_CONF::EXIT_PRE_JUDGE_EXECLP);
    } else {
        // father
        int status = 0;  // child-status
        int syscall_id = 0; // child's syscall
        struct user_regs_struct regs; // reg

        // rf-table init
        init_RF_table(PROBLEM::lang);

        // monitor child
        while (true) {
            // 进程调用 exit() 退出执行后，被设置为僵死状态，这时父进程可以通过 wait4() 系统调用查询子进程是否终结，之后再进行最后的操作，彻底删除进程所占用的内存资源
            if (wait4(executive, &status, 0, &rused) < 0) {
                FM_LOG_WARNING("wait4 failed.");
                exit(JUDGE_CONF::EXIT_JUDGE);
            }

            // exit by itself
            if (WIFEXITED(status)) {
                if (PROBLEM::lang != JUDGE_CONF::LANG_JAVA ||
                    WEXITSTATUS(status) == EXIT_SUCCESS) {
                    FM_LOG_TRACE("OK, normal quit. All is good.");
                } else {
                    FM_LOG_WARNING("oh, some error occured.Abnormal quit.");
                    PROBLEM::result = JUDGE_CONF::RE;
                }
                break;
            }

            // killed by signal
            //WIFSIGNALED(status)如果子进程是因为信号而结束则此宏值为真
            //WIFSTOPPED(status)如果子进程处于暂停执行情况则此宏值为真。一般只有使用WUNTRACED 时才会有此情况。
            //WSTOPSIG(status)取得引发子进程暂停的信号代码，一般会先用WIFSTOPPED 来判断后才使用此宏
            if (WIFSIGNALED(status) ||
                (WIFSTOPPED(status) && WSTOPSIG(status) != SIGTRAP)) { // To filter out the SIGTRAP signal
                int signo = 0;
                if (WIFSIGNALED(status)) {
                    signo = WTERMSIG(status);
                    FM_LOG_WARNING("child signaled by %d : %s", signo, strsignal(signo));
                } else {
                    signo = WSTOPSIG(status);
                    FM_LOG_WARNING("child stop by %d : %s\n", signo, strsignal(signo));
                }

                switch (signo) {
                    case SIGALRM:
                    case SIGXCPU:
                    case SIGVTALRM:
                    case SIGKILL:
                        FM_LOG_TRACE("Well, Time Limit Exeeded");
//                        PROBLEM::time_usage = 0;
//                        PROBLEM::memory_usage = 0;
                        PROBLEM::result = JUDGE_CONF::TLE;
                        break;
                    case SIGXFSZ:
                        FM_LOG_TRACE("File Limit Exceeded");
//                        PROBLEM::time_usage = 0;
//                        PROBLEM::memory_usage = 0;
                        PROBLEM::result = JUDGE_CONF::OLE;
                        break;
                    case SIGSEGV:
                    case SIGFPE:
                    case SIGBUS:
                    case SIGABRT:
                        FM_LOG_TRACE("RE");
//                        PROBLEM::time_usage = 0;
//                        PROBLEM::memory_usage = 0;
                        PROBLEM::result = JUDGE_CONF::RE;
                        break;
                    default:
                        FM_LOG_TRACE("UNKNOWN RE");
//                        PROBLEM::time_usage = 0;
//                        PROBLEM::memory_usage = 0;
                        PROBLEM::result = JUDGE_CONF::RE;
                        break;
                }

                ptrace(PTRACE_KILL, executive, NULL, NULL);
                break;
            }

            // MLE
            PROBLEM::memory_usage = std::max((long int) PROBLEM::memory_usage,
                                             rused.ru_minflt * (getpagesize() / JUDGE_CONF::KILO));

            if (PROBLEM::memory_usage > PROBLEM::memory_limit) {
//                PROBLEM::time_usage = 0;
//                PROBLEM::memory_usage = 0;
                PROBLEM::result = JUDGE_CONF::MLE;
                FM_LOG_TRACE("Well, Memory Limit Exceeded.");
                ptrace(PTRACE_KILL, executive, NULL, NULL);
                break;
            }

            // regs to know child's syscall
            if (ptrace(PTRACE_GETREGS, executive, NULL, &regs) < 0) {
                FM_LOG_WARNING("ptrace PTRACE_GETREGS failed");
                exit(JUDGE_CONF::EXIT_JUDGE);
            }

#ifdef __i386__
            syscall_id = regs.orig_eax;
#else
            syscall_id = regs.orig_rax;
#endif

            // check syscall
            if (syscall_id > 0 && !is_valid_syscall(PROBLEM::lang, syscall_id, executive, regs)) {
                FM_LOG_WARNING("restricted function %d\n", syscall_id);
                PROBLEM::extra_message =
                        "Killed because of using prohibited system call, syscall_id = " + std::to_string(syscall_id);
                if (syscall_id == SYS_rt_sigprocmask) {
                    FM_LOG_WARNING("The glibc failed.");
                } else {
                    FM_LOG_WARNING("restricted function table");
                }
                PROBLEM::result = JUDGE_CONF::RE;
                ptrace(PTRACE_KILL, executive, NULL, NULL);
                break;
            }

            if (ptrace(PTRACE_SYSCALL, executive, NULL, NULL) < 0) {
                FM_LOG_WARNING("ptrace PTRACE_SYSCALL failed.");
                exit(JUDGE_CONF::EXIT_JUDGE);
            }
        }
    }

    if (PROBLEM::result == JUDGE_CONF::SE) {
        PROBLEM::time_usage += (rused.ru_utime.tv_sec * 1000 + rused.ru_utime.tv_usec / 1000);
        PROBLEM::time_usage += (rused.ru_stime.tv_sec * 1000 + rused.ru_stime.tv_usec / 1000);
    }

}

static int compare_output(std::string file_std, std::string file_exec) {
    FILE *fp_std = fopen(file_std.c_str(), "r");
    if (fp_std == NULL) {
        FM_LOG_WARNING("Open standard output file failed.");
        exit(JUDGE_CONF::EXIT_COMPARE);
    }

    FILE *fp_exe = fopen(file_exec.c_str(), "r");
    if (fp_exe == NULL) {
        FM_LOG_WARNING("Open executive output file failed.");
        exit(JUDGE_CONF::EXIT_COMPARE);
    }
    int a, b, Na = 0, Nb = 0;
    enum {
        AC = JUDGE_CONF::AC,
        PE = JUDGE_CONF::PE,
        WA = JUDGE_CONF::WA
    } status = AC;
    while (true) {
        a = fgetc(fp_std);
        b = fgetc(fp_exe);
        Na++, Nb++;

        //统一\r和\n之间的区别
        if (a == '\r') {
            a = fgetc(fp_std);
            Na++;
        }
        if (b == '\r') {
            b = fgetc(fp_std);
            Nb++;
        }
#define is_space_char(a) ((a == ' ') || (a == '\t') || (a == '\n'))

        if (feof(fp_std) && feof(fp_exe)) {
            //文件结束
            break;
        } else if (feof(fp_std) || feof(fp_exe)) {
            //如果只有一个文件结束
            //但是另一个文件的末尾是回车
            //那么也当做AC处理
            FILE *fp_tmp;
            if (feof(fp_std)) {
                if (!is_space_char(b)) {
                    FM_LOG_TRACE("Well, Wrong Answer.");
                    status = WA;
                    break;
                }
                fp_tmp = fp_exe;
            } else {
                if (!is_space_char(a)) {
                    FM_LOG_TRACE("Well, Wrong Answer.");
                    status = WA;
                    break;
                }
                fp_tmp = fp_std;
            }
            int c;
            while ((c = fgetc(fp_tmp)) != EOF) {
                if (c == '\r') c = '\n';
                if (!is_space_char(c)) {
                    FM_LOG_TRACE("Well, Wrong Answer.");
                    status = WA;
                    break;
                }
            }
            break;
        }

        //如果两个字符不同
        if (a != b) {
            status = PE;
            //过滤空白字符
            if (is_space_char(a) && is_space_char(b)) {
                continue;
            }
            if (is_space_char(a)) {
                //a是空白字符，过滤，退回b以便下一轮循环
                ungetc(b, fp_exe);
                Nb--;
            } else if (is_space_char(b)) {
                ungetc(a, fp_std);
                Na--;
            } else {
                FM_LOG_TRACE("Well, Wrong Answer.");
                status = WA;
                break;
            }
        }
    }
    fclose(fp_std);
    fclose(fp_exe);
    return status;
}

static void run_spj() {
    // support ljudge style special judge
    const char origin_name[3][16] = {"./in.in", "./out.out", "./out.txt"};
    const char target_name[4][16] = {"/input", "/output", "/user_output", "/user_code"};
    for (int i = 0; i < 4; i++) {
        std::string origin_path = (i != 3) ? origin_name[i] : PROBLEM::code_path;
        std::string target_path = PROBLEM::run_dir + target_name[i];
        //symlink()以参数newpath 指定的名称来建立一个新的连接(符号连接)到参数oldpath 所指定的已存在文件.
        // 参数oldpath 指定的文件不一定要存在, 如果参数newpath 指定的名称为一已存在的文件则不会建立连接.
        if (EXIT_SUCCESS != symlink(origin_path.c_str(), target_path.c_str()))
            FM_LOG_WARNING("Create symbolic link from '%s' to '%s' failed,%d:%s.", origin_path.c_str(),
                           target_path.c_str(), errno, strerror(errno));
    }
    pid_t spj_pid = fork();
    int status = 0;
    if (spj_pid < 0) {
        FM_LOG_WARNING("fork for special judge failed.So sad.");
        exit(JUDGE_CONF::EXIT_COMPARE_SPJ);
    } else if (spj_pid == 0) {
        FM_LOG_TRACE("Woo, I will start special judge!");
        stdin = freopen(PROBLEM::input_file.c_str(), "r", stdin); // ljudge style
        stdout = freopen(PROBLEM::spj_output_file.c_str(), "w", stdout);
        if (stdin == NULL || stdout == NULL) {
            FM_LOG_WARNING("redirect io in spj failed.");
            exit(JUDGE_CONF::EXIT_COMPARE_SPJ);
        }
        // spj time-limit
        if (EXIT_SUCCESS != malarm(ITIMER_REAL, JUDGE_CONF::SPJ_TIME_LIMIT)) {
            FM_LOG_WARNING("Set time limit for spj failed.");
            exit(JUDGE_CONF::EXIT_COMPARE_SPJ);
        }

        security_control_spj();

        if (PROBLEM::spj_lang != JUDGE_CONF::LANG_JAVA) {
            execl("./SpecialJudge", "SpecialJudge", "user_output", NULL);
        } else {
            execlp("java", "java", "SpecialJudge", NULL);
        }

        exit(JUDGE_CONF::EXIT_COMPARE_SPJ_FORK);
    } else {
        if (wait4(spj_pid, &status, 0, NULL) < 0) {
            FM_LOG_WARNING("wait4 failed.");
            exit(JUDGE_CONF::EXIT_COMPARE_SPJ);
        }

        if (WIFEXITED(status)) {
            int spj_exit_code = WEXITSTATUS(status);
            if (spj_exit_code >= 0 && spj_exit_code < 4) {
                FM_LOG_TRACE("Well, SpecialJudge program normally quit.All is good.");
                // get spj result
                switch (spj_exit_code) {
                    case 0:
                        PROBLEM::result = JUDGE_CONF::AC;
                        break;
                    case 1:
                        PROBLEM::result = JUDGE_CONF::WA;
                        break;
                    case 2:
                        PROBLEM::result = JUDGE_CONF::PE;
                        break;
                }
                return;
            } else {
                FM_LOG_WARNING("I am sorry to tell you that the special judge program abnormally terminated. %d",
                               WEXITSTATUS(status));
            }
        } else if (WIFSIGNALED(status) && WTERMSIG(status) == SIGALRM) {
            FM_LOG_WARNING("Well, the special judge program consume too much time.");
        } else {
            FM_LOG_WARNING("Actually, I do not kwon why the special judge program dead.");
        }
    }
}

static void run_spj_new() {
    // support ljudge style special judge
    const char origin_name[3][16] = {"./in.in", "./out.out", "./out.txt"};
    const char target_name[4][16] = {"/input", "/output", "/user_output", "/user_code"};
    for (int i = 0; i < 4; i++) {
        FM_LOG_DEBUG("before link output the PROBLEM::code_path = %s", PROBLEM::code_path.c_str());
        std::string origin_path = (i != 3) ? origin_name[i] : PROBLEM::code_path;
        std::string target_path = PROBLEM::run_dir + target_name[i];
        //symlink()以参数newpath 指定的名称来建立一个新的连接(符号连接)到参数oldpath 所指定的已存在文件.
        // 参数oldpath 指定的文件不一定要存在, 如果参数newpath 指定的名称为一已存在的文件则不会建立连接.
        if (EXIT_SUCCESS != symlink(origin_path.c_str(), target_path.c_str()))
            FM_LOG_WARNING("Create symbolic link from '%s' to '%s' failed,%d:%s.", origin_path.c_str(),
                           target_path.c_str(), errno, strerror(errno));
    }
    pid_t spj_pid = fork();
    int status = 0;
    if (spj_pid < 0) {
        FM_LOG_WARNING("fork for special judge failed.So sad.");
        exit(JUDGE_CONF::EXIT_COMPARE_SPJ);
    } else if (spj_pid == 0) {
        FM_LOG_TRACE("Woo, I will start special judge!");
        stdin = freopen(PROBLEM::input_file.c_str(), "r", stdin); // ljudge style
        stdout = freopen(PROBLEM::spj_output_file.c_str(), "w", stdout);
        if (stdin == NULL || stdout == NULL) {
            FM_LOG_WARNING("redirect io in spj failed.");
            exit(JUDGE_CONF::EXIT_COMPARE_SPJ);
        }
        // spj time-limit
        if (EXIT_SUCCESS != malarm(ITIMER_REAL, JUDGE_CONF::SPJ_TIME_LIMIT)) {
            FM_LOG_WARNING("Set time limit for spj failed.");
            exit(JUDGE_CONF::EXIT_COMPARE_SPJ);
        }

        security_control_spj();

        //use testlib.h run
        if (PROBLEM::spj_lang != JUDGE_CONF::LANG_JAVA) {
            execl("./SpecialJudge", "./in.in", "./out.ans", "./out.txt");
        } else {
            execlp("java", "java", "SpecialJudge", NULL);
        }

        exit(JUDGE_CONF::EXIT_COMPARE_SPJ_FORK);
    } else {
        if (wait4(spj_pid, &status, 0, NULL) < 0) {
            FM_LOG_WARNING("wait4 failed.");
            exit(JUDGE_CONF::EXIT_COMPARE_SPJ);
        }

        if (WIFEXITED(status)) {
            int spj_exit_code = WEXITSTATUS(status);
            if (spj_exit_code >= 0 && spj_exit_code < 4) {
                FM_LOG_TRACE("Well, SpecialJudge program normally quit.All is good.");
                // get spj result
                switch (spj_exit_code) {
                    case 0:
                        PROBLEM::result = JUDGE_CONF::AC;
                        break;
                    case 1:
                        PROBLEM::result = JUDGE_CONF::WA;
                        break;
                    case 2:
                        PROBLEM::result = JUDGE_CONF::PE;
                        break;
                }
                return;
            } else {
                FM_LOG_WARNING(
                        "the spj_exit_code = %d and I am sorry to tell you that the special judge program abnormally terminated. %d ",
                        spj_exit_code, WEXITSTATUS(status));
            }
        } else if (WIFSIGNALED(status) && WTERMSIG(status) == SIGALRM) {
            FM_LOG_WARNING("Well, the special judge program consume too much time.");
        } else {
            FM_LOG_WARNING("Actually, I do not kwon why the special judge program dead.");
        }
    }
}

int main(int argc, char *argv[]) {
    parse_arguments(argc, argv);

    log_open((PROBLEM::run_dir + "/core_log.txt").c_str());

    // callback at exit
    // 很多时候我们需要在程序退出的时候做一些诸如释放资源的操作，但程序退出的方式有很多种，比如main()函数运行结束、
    // 在程序的某个地方用exit() 结束程序、用户通过Ctrl+C或Ctrl+break操作来终止程序等等，
    // 因此需要有一种与程序退出方式无关的方法来进行程序退出时的必要处理。
    // 方法就 是用atexit()函数来注册程序正常终止时要被调用的函数
    // 这边的意思是正常退出的时候调用output_result()函数
    atexit(output_result);

    // root check
    // linux系统中每个进程都有2个用户ID，分别为用户ID（uid）和有效用户ID（euid），
    // UID一般表示进程的创建者（属于哪个用户创建），而EUID表示进程对于文件和资源的访问权限（具备等同于哪个用户的权限）
    /** testlib.h的返回状态码
     * _ok = 0,
     * _wa = 1,
     * _pe = 2,
     * _fail = 3,
     * _dirt = 4,
     * _points = 5,
     * _unexpected_eof = 8,
     * _partially = 16
     *
     */
    if (geteuid() != 0) {
        FM_LOG_FATAL("You must run this program as root.");
        exit(JUDGE_CONF::EXIT_UNPRIVILEGED);
    }

    JUDGE_CONF::JUDGE_TIME_LIMIT += PROBLEM::time_limit;

    // ITIMER_REAL 是Linux中的定时器，以系统真实时间来计算，发送SIGALRM信号
    // ITIMER_REAL: 以逝去时间递减
    if (EXIT_SUCCESS != malarm(ITIMER_REAL, JUDGE_CONF::JUDGE_TIME_LIMIT)) {
        FM_LOG_WARNING("Set the alarm for this judge program failed, %d: %s", errno, strerror(errno));
        exit(JUDGE_CONF::EXIT_VERY_FIRST);
    }
    signal(SIGALRM, timeout);

    judge();

    if (PROBLEM::spj) {
        run_spj_new();
    } else {
        if (PROBLEM::result == JUDGE_CONF::SE) {
            PROBLEM::result = compare_output(PROBLEM::output_file, PROBLEM::exec_output);
        }
    }

    return 0;
}

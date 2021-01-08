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

extern int errno;

// output result
static void output_result() {
    FILE* result_file = fopen(PROBLEM::result_file.c_str(), "w");
    switch (PROBLEM::result){
        case 1:PROBLEM::status = "Compile Error";break;
        case 2:PROBLEM::status = "Time Limit Exceeded";break;
        case 3:PROBLEM::status = "Memory Limit Exceeded";break;
        case 4:PROBLEM::status = "Output Limit Exceeded";break;
        case 5:PROBLEM::status = "Runtime Error";break;
        case 6:PROBLEM::status = "Wrong Answer";break;
        case 7:PROBLEM::status = "Accepted";break;
        case 8:PROBLEM::status = "Presentation Error";break;
        default:PROBLEM::status = "System Error";break;
    }
    fprintf(result_file, "%d\n", PROBLEM::result);
    fprintf(result_file, "%d\n", PROBLEM::time_usage);
    fprintf(result_file, "%d\n", PROBLEM::memory_usage);
    fprintf(result_file, "%s\n", PROBLEM::extra_message.c_str());

    FM_LOG_TRACE("The final result is %s %d %d %s",PROBLEM::status.c_str(), PROBLEM::time_usage,PROBLEM::memory_usage, PROBLEM::extra_message.c_str());
}

// parse arguments
static void parse_arguments(int argc, char* argv[]) {
    int opt;
    extern char *optarg;

    while ((opt = getopt(argc, argv, "l:t:m:d:s")) != -1) {
        switch (opt) {
            case 'l': PROBLEM::lang         = atoi(optarg);   break;
            case 't': PROBLEM::time_limit   = atoi(optarg);   break;
            case 'm': PROBLEM::memory_limit = atoi(optarg);   break;
            case 's': PROBLEM::spj          = true;           break;
            case 'd': PROBLEM::run_dir      = optarg;         break;
            default:
                FM_LOG_WARNING("Unknown option provided: -%c %s", opt, optarg);
                exit(JUDGE_CONF::EXIT_BAD_PARAM);
        }
    }

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
}

// timeout callback
static void timeout(int signal) {
    //超时的回调函数
    if (signal == SIGALRM) {
        exit(JUDGE_CONF::EXIT_TIMEOUT);
    }
}

// set time limit
static int malarm(int which, int milliseconds) {
    struct itimerval t;
    t.it_value.tv_sec     = milliseconds / 1000;
    t.it_value.tv_usec    = milliseconds % 1000 * 1000; //microsecond
    t.it_interval.tv_sec  = 0;
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
    struct passwd *nobody = getpwnam("nobody");
    if (nobody == NULL){
        FM_LOG_WARNING("Well, where is nobody? I cannot live without him. %d: %s", errno, strerror(errno));
        exit(JUDGE_CONF::EXIT_SET_SECURITY);
    }

    // chdir
    if (EXIT_SUCCESS != chdir(PROBLEM::run_dir.c_str())) {
        FM_LOG_WARNING("chdir(%s) failed, %d: %s", PROBLEM::run_dir.c_str(), errno, strerror(errno));
        exit(JUDGE_CONF::EXIT_SET_SECURITY);
    }

    char cwd[1024], *tmp = getcwd(cwd, 1024);
    if (tmp == NULL) {
        FM_LOG_WARNING("Oh, where i am now? I cannot getcwd. %d: %s", errno, strerror(errno));
        exit(JUDGE_CONF::EXIT_SET_SECURITY);
    }

    // chroot
    // JVM cannot run with chroot/setuid
    if (PROBLEM::lang != JUDGE_CONF::LANG_JAVA) {
        if (EXIT_SUCCESS != chroot(cwd)) {
            FM_LOG_WARNING("chroot(%s) failed. %d: %s", cwd, errno, strerror(errno));
            exit(JUDGE_CONF::EXIT_SET_SECURITY);
        }
        // setuid
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

/*
 * program runtime limit
 * cpu-time/stack-size/output-size
 */
static void set_limit() {
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
    getrlimit(RLIMIT_STACK, &lim);

    int rlim = JUDGE_CONF::STACK_SIZE_LIMIT * JUDGE_CONF::KILO;
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
        if(syscall_id == SYS_open) {
#if __WORDSIZE == 32
            addr = regs.ebx;
#else
            addr = regs.rdi;
#endif
#define LONGSIZE sizeof(long)
            union u{ unsigned long val; char chars[LONGSIZE]; }data;
            unsigned long i = 0, j = 0, k = 0;
            char filename[300];
            while (true)
            {
                data.val = ptrace(PTRACE_PEEKDATA, child, addr + i,  NULL);
                i += LONGSIZE;
                for (j = 0; j < LONGSIZE && data.chars[j] > 0 && k < 256; j++)
                {
                    filename[k++] = data.chars[j];
                }
                if (j < LONGSIZE && data.chars[j] == 0)
                    break;
            }
            filename[k] = 0;
            //FM_LOG_TRACE("syscall open: filename: %s", filename);
            if (strstr(filename, "..") != NULL)
            {
                return false;
            }
            if (strstr(filename, "/proc/") == filename)
            {
                return true;
            }
            if (strstr(filename, "/dev/tty") == filename)
            {
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
        io_redirect();
        security_control();

        int real_time_limit = PROBLEM::time_limit;
        if (EXIT_SUCCESS != malarm(ITIMER_REAL, real_time_limit)) {
            exit(JUDGE_CONF::EXIT_PRE_JUDGE);
        }

        set_limit();

        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            exit(JUDGE_CONF::EXIT_PRE_JUDGE_PTRACE);
        }

        /// running
        if (PROBLEM::lang != JUDGE_CONF::LANG_JAVA){
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
            if (WIFSIGNALED(status) || (WIFSTOPPED(status) && WSTOPSIG(status) != SIGTRAP)) { // To filter out the SIGTRAP signal
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
            PROBLEM::memory_usage = std::max((long int)PROBLEM::memory_usage, rused.ru_minflt * (getpagesize() / JUDGE_CONF::KILO));

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
                PROBLEM::extra_message = "Killed because of using prohibited system call, syscall_id = " + std::to_string(syscall_id);
                if (syscall_id == SYS_rt_sigprocmask){
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

    if (PROBLEM::result == JUDGE_CONF::SE){
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
    }status = AC;
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

        if (feof(fp_std) && feof(fp_exe)){
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
    for (int i = 0; i < 4; i++)
    {
        std::string origin_path = (i != 3) ? origin_name[i] : PROBLEM::code_path;
        std::string target_path = PROBLEM::run_dir + target_name[i];
        if (EXIT_SUCCESS != symlink(origin_path.c_str(), target_path.c_str()))
            FM_LOG_WARNING("Create symbolic link from '%s' to '%s' failed,%d:%s.", origin_path.c_str(), target_path.c_str(), errno, strerror(errno));
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
                return ;
            } else {
                FM_LOG_WARNING("I am sorry to tell you that the special judge program abnormally terminated. %d", WEXITSTATUS(status));
            }
        } else if (WIFSIGNALED(status) && WTERMSIG(status) == SIGALRM) {
            FM_LOG_WARNING("Well, the special judge program consume too much time.");
        } else {
            FM_LOG_WARNING("Actually, I do not kwon why the special judge program dead.");
        }
    }
}

int main(int argc, char *argv[]) {
    log_open("./core_log.txt");

    // callback at exit
    atexit(output_result);

    // root check
    if (geteuid() != 0) {
        FM_LOG_FATAL("You must run this program as root.");
        exit(JUDGE_CONF::EXIT_UNPRIVILEGED);
    }

    parse_arguments(argc, argv);

    JUDGE_CONF::JUDGE_TIME_LIMIT += PROBLEM::time_limit;

    if (EXIT_SUCCESS != malarm(ITIMER_REAL, JUDGE_CONF::JUDGE_TIME_LIMIT)) {
        FM_LOG_WARNING("Set the alarm for this judge program failed, %d: %s", errno, strerror(errno));
        exit(JUDGE_CONF::EXIT_VERY_FIRST);
    }
    signal(SIGALRM, timeout);

    judge();

    if (PROBLEM::spj) {
        run_spj();
    } else {
        if (PROBLEM::result == JUDGE_CONF::SE) {
            PROBLEM::result = compare_output(PROBLEM::output_file, PROBLEM::exec_output);
        }
    }

    return 0;
}

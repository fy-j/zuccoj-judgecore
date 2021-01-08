#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>

#include "core.h"
#include "logger.h"

extern int errno;

// suffix check
static bool has_suffix(const std::string &str, const std::string &suffix) {
    return str.size() >= suffix.size() &&
           str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// output result
static void output_result() {
    FILE* result_file = fopen(PROBLEM::result_file.c_str(), "w");
    if (PROBLEM::result == JUDGE_CONF::CE) {
        PROBLEM::status = "0";
    } else {
        PROBLEM::status = "1";
    }
    fprintf(result_file, "%s\n", PROBLEM::status.c_str());
    fprintf(result_file, "%s\n", PROBLEM::extra_message.c_str());

    FM_LOG_TRACE("The final result is %s %s", PROBLEM::status.c_str(), PROBLEM::extra_message.c_str());
}

// parse arguments
static void parse_arguments(int argc, char* argv[]) {
    int opt;
    extern char *optarg;

    while ((opt = getopt(argc, argv, "c:d:")) != -1) {
        switch (opt) {
            case 'c': PROBLEM::code_path    = optarg;         break;
            case 'd': PROBLEM::run_dir      = optarg;         break;
            default:
                FM_LOG_WARNING("Unknown option provided: -%c %s", opt, optarg);
                exit(JUDGE_CONF::EXIT_BAD_PARAM);
        }
    }

    if (has_suffix(PROBLEM::code_path, ".cpp")) {
        PROBLEM::lang = JUDGE_CONF::LANG_CPP;
    } else if (has_suffix(PROBLEM::code_path, ".c")) {
        PROBLEM::lang = JUDGE_CONF::LANG_C;
    } else if (has_suffix(PROBLEM::code_path, ".java")) {
        PROBLEM::lang = JUDGE_CONF::LANG_JAVA;
    } else {
        FM_LOG_WARNING("It seems that you give me a language which I do not known now: %d", PROBLEM::lang);
        exit(JUDGE_CONF::EXIT_BAD_PARAM);
    }

    PROBLEM::exec_file = PROBLEM::run_dir + "/Main";
    PROBLEM::exec_output = PROBLEM::run_dir + "/out.txt";
    PROBLEM::result_file = PROBLEM::run_dir + "/result.txt";
    PROBLEM::stdout_file_compiler = PROBLEM::run_dir + "/stdout_file_compiler.txt";
    PROBLEM::stderr_file_compiler = PROBLEM::run_dir + "/stderr_file_compiler.txt";

    if (PROBLEM::lang == JUDGE_CONF::LANG_JAVA) {
        PROBLEM::exec_file = PROBLEM::run_dir + "/Main";
    }
}

// get compile error message
static void get_compile_error_message() {
    FILE *ce_msg = fopen(PROBLEM::stderr_file_compiler.c_str(), "r");
    std::string message = "";
    char tmp[1024];
    while (fgets(tmp, sizeof(tmp), ce_msg)) {
        message += tmp;
    }

    PROBLEM::extra_message = message;
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

// compiler source code
static void compiler_source_code() {
    pid_t compiler = fork();
    int status = 0;
    if (compiler < 0) {
        FM_LOG_WARNING("error fork compiler");
        exit(JUDGE_CONF::EXIT_COMPILE);
    } else if (compiler == 0) {
        // child: compile

        log_add_info("compiler");
        stdout = freopen(PROBLEM::stdout_file_compiler.c_str(), "w", stdout);
        stderr = freopen(PROBLEM::stderr_file_compiler.c_str(), "w", stderr);
        if (stdout == NULL || stderr == NULL) {
            FM_LOG_WARNING("error to freopen in compiler: stdout(%p) stderr(%p)", stdout, stderr);
            exit(JUDGE_CONF::EXIT_COMPILE);
        }

        // compiler time limit
        malarm(ITIMER_REAL, JUDGE_CONF::COMPILE_TIME_LIMIT);

        switch (PROBLEM::lang) {
            case JUDGE_CONF::LANG_C:
                FM_LOG_TRACE("Start: gcc -o %s %s -static -w -lm -std=c99 -O2 -DONLINE_JUDGE", PROBLEM::exec_file.c_str(), PROBLEM::code_path.c_str());
                execlp("gcc", "gcc", "-o", PROBLEM::exec_file.c_str(), PROBLEM::code_path.c_str(), "-static", "-w", "-lm", "-std=c99", "-O2", "-DONLINE_JUDGE", NULL);
                break;
            case JUDGE_CONF::LANG_CPP:
                FM_LOG_TRACE("Start: g++ -o %s %s -static -w -lm -O2 -DONLINE_JUDGE", PROBLEM::exec_file.c_str(), PROBLEM::code_path.c_str());
                execlp("g++", "g++", "-o", PROBLEM::exec_file.c_str(), PROBLEM::code_path.c_str(), "-static", "-w", "-lm", "-O2", "-std=c++11", "-DONLINE_JUDGE", NULL);
                break;
            case JUDGE_CONF::LANG_JAVA:
                FM_LOG_TRACE("Start:javac %s -d %s", PROBLEM::code_path.c_str(), PROBLEM::run_dir.c_str());
                execlp("javac", "javac", PROBLEM::code_path.c_str(), "-d", PROBLEM::run_dir.c_str(), NULL);
                break;

            /// TODO: new lang supported
            default:
                exit(JUDGE_CONF::EXIT_BAD_PARAM);
        }

        FM_LOG_WARNING("exec compiler error");
        exit(JUDGE_CONF::EXIT_COMPILE);
    } else {
        // father

        // block until child end
        pid_t w = waitpid(compiler, &status, WUNTRACED);
        if (w == -1) {
            FM_LOG_WARNING("waitpid error");
            exit(JUDGE_CONF::EXIT_COMPILE);
        }

        FM_LOG_TRACE("compiler finished");
        if (WIFEXITED(status)) {
            // compiler exit by itself
            if (EXIT_SUCCESS == WEXITSTATUS(status)) {
                FM_LOG_TRACE("compile succeeded.");
            } else if (JUDGE_CONF::GCC_COMPILE_ERROR == WEXITSTATUS(status)){
                // CE
                FM_LOG_TRACE("compile error");
                PROBLEM::result = JUDGE_CONF::CE;
                get_compile_error_message();
                exit(JUDGE_CONF::EXIT_OK);
            } else {
                FM_LOG_WARNING("Unknown error occur when compiling the source code.Exit status %d", WEXITSTATUS(status));
                exit(JUDGE_CONF::EXIT_COMPILE);
            }
        } else {
            // be stopped
            if (WIFSIGNALED(status)){
                if (SIGALRM == WTERMSIG(status)) {
                    FM_LOG_WARNING("Compile time out");
                    PROBLEM::result = JUDGE_CONF::CE;
                    PROBLEM::extra_message = "Compile Out of Time Limit";
                    exit(JUDGE_CONF::EXIT_OK);
                } else {
                    FM_LOG_WARNING("Unknown signal when compile the source code.");
                }
            } else if (WIFSTOPPED(status)){
                FM_LOG_WARNING("The compile process stopped by signal");
            } else {
                FM_LOG_WARNING("I don't kwon why the compile process stopped");
            }
            exit(JUDGE_CONF::EXIT_COMPILE);
        }
    }
}

int main(int argc, char *argv[]) {
    log_open("./compiler_log.txt");

    // callback at exit
    atexit(output_result);

    // root check
    if (geteuid() != 0) {
        FM_LOG_FATAL("You must run this program as root.");
        exit(JUDGE_CONF::EXIT_UNPRIVILEGED);
    }

    parse_arguments(argc, argv);

    if (EXIT_SUCCESS != malarm(ITIMER_REAL, JUDGE_CONF::JUDGE_TIME_LIMIT)) {
        FM_LOG_WARNING("Set the alarm for this judge program failed, %d: %s", errno, strerror(errno));
        exit(JUDGE_CONF::EXIT_VERY_FIRST);
    }
    signal(SIGALRM, timeout);

    compiler_source_code();

    return 0;
}

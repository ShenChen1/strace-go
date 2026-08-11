#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void)
{
    int dup_fd = (int)syscall(SYS_fcntl, STDIN_FILENO, F_DUPFD, 20);
    int cloexec_fd = (int)syscall(SYS_fcntl, STDIN_FILENO, F_DUPFD_CLOEXEC, 30);
    int file_flags = (int)syscall(SYS_fcntl, STDIN_FILENO, F_GETFL, 0);
    if (dup_fd < 0 || cloexec_fd < 0 || file_flags < 0) {
        return 1;
    }
    (void)close(dup_fd);
    (void)close(cloexec_fd);
    return 0;
}

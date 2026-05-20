#include <unistd.h>
#include <sys/syscall.h>
int main() {
    syscall(163, "nonexistent");
    return 0;
}

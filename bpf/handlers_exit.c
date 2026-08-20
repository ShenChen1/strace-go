#include "handler_common.h"

#define STRACE_GO_HANDLER_FAMILY 1
#define STRACE_GO_HANDLER_EXIT 1

#include "exit_dispatch.h"
#include "exit_direct_dispatch.h"
#include "nested_fd_path_exit_dispatch.h"
#include "quota_dispatch.h"
#include "mount_query_dispatch.h"

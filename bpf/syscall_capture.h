#define CAPTURE_ARGS(sys_id, e) \
	switch (sys_id) { \
		case 43: /* accept */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 288: /* accept4 */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 21: /* access */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 163: /* acct */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 248: /* add_key */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 159: /* adjtimex */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 49: /* bind */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 321: /* bpf */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 451: /* cachestat */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 80: /* chdir */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 90: /* chmod */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 92: /* chown */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 161: /* chroot */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 305: /* clock_adjtime */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 229: /* clock_getres */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 228: /* clock_gettime */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 230: /* clock_nanosleep */ \
			(e)->ptr = (e)->args[2]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[2]); \
			break; \
		case 227: /* clock_settime */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 56: /* clone */ \
			(e)->ptr = (e)->args[2]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[2]); \
			break; \
		case 435: /* clone3 */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 42: /* connect */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 326: /* copy_file_range */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 85: /* creat */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 176: /* delete_module */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 233: /* epoll_ctl */ \
			(e)->ptr = (e)->args[3]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[3]); \
			break; \
		case 281: /* epoll_pwait */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 441: /* epoll_pwait2 */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 232: /* epoll_wait */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 59: /* execve */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 322: /* execveat */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 269: /* faccessat */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 439: /* faccessat2 */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 301: /* fanotify_mark */ \
			(e)->ptr = (e)->args[4]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[4]); \
			break; \
		case 268: /* fchmodat */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 452: /* fchmodat2 */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 260: /* fchownat */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 193: /* fgetxattr */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 468: /* file_getattr */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 469: /* file_setattr */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 313: /* finit_module */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 196: /* flistxattr */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 199: /* fremovexattr */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 431: /* fsconfig */ \
			(e)->ptr = (e)->args[2]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[2]); \
			break; \
		case 190: /* fsetxattr */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 430: /* fsopen */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 433: /* fspick */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 138: /* fstatfs */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 202: /* futex */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 456: /* futex_requeue */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 455: /* futex_wait */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 449: /* futex_waitv */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 454: /* futex_wake */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 261: /* futimesat */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 239: /* get_mempolicy */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 274: /* get_robust_list */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 309: /* getcpu */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 79: /* getcwd */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 78: /* getdents */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 217: /* getdents64 */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 115: /* getgroups */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 36: /* getitimer */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 52: /* getpeername */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 318: /* getrandom */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 120: /* getresgid */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 118: /* getresuid */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 97: /* getrlimit */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 98: /* getrusage */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 51: /* getsockname */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 55: /* getsockopt */ \
			(e)->ptr = (e)->args[3]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[3]); \
			break; \
		case 96: /* gettimeofday */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 191: /* getxattr */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 464: /* getxattrat */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 175: /* init_module */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 254: /* inotify_add_watch */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 210: /* io_cancel */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 208: /* io_getevents */ \
			(e)->ptr = (e)->args[3]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[3]); \
			break; \
		case 333: /* io_pgetevents */ \
			(e)->ptr = (e)->args[3]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[3]); \
			break; \
		case 206: /* io_setup */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 209: /* io_submit */ \
			(e)->ptr = (e)->args[2]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[2]); \
			break; \
		case 426: /* io_uring_enter */ \
			(e)->ptr = (e)->args[4]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[4]); \
			break; \
		case 427: /* io_uring_register */ \
			(e)->ptr = (e)->args[2]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[2]); \
			break; \
		case 425: /* io_uring_setup */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 320: /* kexec_file_load */ \
			(e)->ptr = (e)->args[3]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[3]); \
			break; \
		case 246: /* kexec_load */ \
			(e)->ptr = (e)->args[2]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[2]); \
			break; \
		case 445: /* landlock_add_rule */ \
			(e)->ptr = (e)->args[2]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[2]); \
			break; \
		case 444: /* landlock_create_ruleset */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 94: /* lchown */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 192: /* lgetxattr */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 86: /* link */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 265: /* linkat */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 458: /* listmount */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 194: /* listxattr */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 465: /* listxattrat */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 195: /* llistxattr */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 198: /* lremovexattr */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 189: /* lsetxattr */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 459: /* lsm_get_self_attr */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 461: /* lsm_list_modules */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 460: /* lsm_set_self_attr */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 237: /* mbind */ \
			(e)->ptr = (e)->args[3]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[3]); \
			break; \
		case 319: /* memfd_create */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 256: /* migrate_pages */ \
			(e)->ptr = (e)->args[2]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[2]); \
			break; \
		case 27: /* mincore */ \
			(e)->ptr = (e)->args[2]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[2]); \
			break; \
		case 83: /* mkdir */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 258: /* mkdirat */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 133: /* mknod */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 259: /* mknodat */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 154: /* modify_ldt */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 165: /* mount */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 442: /* mount_setattr */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 429: /* move_mount */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 279: /* move_pages */ \
			(e)->ptr = (e)->args[2]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[2]); \
			break; \
		case 245: /* mq_getsetattr */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 244: /* mq_notify */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 240: /* mq_open */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 243: /* mq_timedreceive */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 242: /* mq_timedsend */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 241: /* mq_unlink */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 71: /* msgctl */ \
			(e)->ptr = (e)->args[2]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[2]); \
			break; \
		case 70: /* msgrcv */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 69: /* msgsnd */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 303: /* name_to_handle_at */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 35: /* nanosleep */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 5: /* fstat */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 262: /* newfstatat */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 6: /* lstat */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 4: /* stat */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 63: /* uname */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 2: /* open */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 304: /* open_by_handle_at */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 428: /* open_tree */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 467: /* open_tree_attr */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 257: /* openat */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 437: /* openat2 */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 298: /* perf_event_open */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 424: /* pidfd_send_signal */ \
			(e)->ptr = (e)->args[2]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[2]); \
			break; \
		case 22: /* pipe */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 293: /* pipe2 */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 155: /* pivot_root */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 7: /* poll */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 271: /* ppoll */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 17: /* pread64 */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 295: /* preadv */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 327: /* preadv2 */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 302: /* prlimit64 */ \
			(e)->ptr = (e)->args[2]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[2]); \
			break; \
		case 440: /* process_madvise */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 310: /* process_vm_readv */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 311: /* process_vm_writev */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 270: /* pselect6 */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 18: /* pwrite64 */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 296: /* pwritev */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 328: /* pwritev2 */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 179: /* quotactl */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 443: /* quotactl_fd */ \
			(e)->ptr = (e)->args[3]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[3]); \
			break; \
		case 0: /* read */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 89: /* readlink */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 267: /* readlinkat */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 19: /* readv */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 169: /* reboot */ \
			(e)->ptr = (e)->args[3]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[3]); \
			break; \
		case 45: /* recvfrom */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 299: /* recvmmsg */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 47: /* recvmsg */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 197: /* removexattr */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 466: /* removexattrat */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 82: /* rename */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 264: /* renameat */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 316: /* renameat2 */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 249: /* request_key */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 84: /* rmdir */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 334: /* rseq */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 13: /* rt_sigaction */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 127: /* rt_sigpending */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 14: /* rt_sigprocmask */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 129: /* rt_sigqueueinfo */ \
			(e)->ptr = (e)->args[2]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[2]); \
			break; \
		case 130: /* rt_sigsuspend */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 128: /* rt_sigtimedwait */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 297: /* rt_tgsigqueueinfo */ \
			(e)->ptr = (e)->args[3]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[3]); \
			break; \
		case 204: /* sched_getaffinity */ \
			(e)->ptr = (e)->args[2]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[2]); \
			break; \
		case 315: /* sched_getattr */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 143: /* sched_getparam */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 148: /* sched_rr_get_interval */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 203: /* sched_setaffinity */ \
			(e)->ptr = (e)->args[2]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[2]); \
			break; \
		case 314: /* sched_setattr */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 142: /* sched_setparam */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 144: /* sched_setscheduler */ \
			(e)->ptr = (e)->args[2]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[2]); \
			break; \
		case 317: /* seccomp */ \
			(e)->ptr = (e)->args[2]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[2]); \
			break; \
		case 23: /* select */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 65: /* semop */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 220: /* semtimedop */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 307: /* sendmmsg */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 46: /* sendmsg */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 44: /* sendto */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 238: /* set_mempolicy */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 273: /* set_robust_list */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 218: /* set_tid_address */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 171: /* setdomainname */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 116: /* setgroups */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 170: /* sethostname */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 38: /* setitimer */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 160: /* setrlimit */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 54: /* setsockopt */ \
			(e)->ptr = (e)->args[3]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[3]); \
			break; \
		case 164: /* settimeofday */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 188: /* setxattr */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 463: /* setxattrat */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 30: /* shmat */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 31: /* shmctl */ \
			(e)->ptr = (e)->args[2]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[2]); \
			break; \
		case 67: /* shmdt */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 131: /* sigaltstack */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 282: /* signalfd */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 289: /* signalfd4 */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 53: /* socketpair */ \
			(e)->ptr = (e)->args[3]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[3]); \
			break; \
		case 275: /* splice */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 137: /* statfs */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 457: /* statmount */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 332: /* statx */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 168: /* swapoff */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 167: /* swapon */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 88: /* symlink */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 266: /* symlinkat */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 99: /* sysinfo */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 103: /* syslog */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 201: /* time */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 222: /* timer_create */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 224: /* timer_gettime */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 223: /* timer_settime */ \
			(e)->ptr = (e)->args[2]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[2]); \
			break; \
		case 287: /* timerfd_gettime */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 286: /* timerfd_settime */ \
			(e)->ptr = (e)->args[2]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[2]); \
			break; \
		case 100: /* times */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 76: /* truncate */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 87: /* unlink */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 263: /* unlinkat */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 136: /* ustat */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 132: /* utime */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 280: /* utimensat */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 235: /* utimes */ \
			(e)->ptr = (e)->args[0]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[0]); \
			break; \
		case 278: /* vmsplice */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 61: /* wait4 */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 247: /* waitid */ \
			(e)->ptr = (e)->args[2]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[2]); \
			break; \
		case 1: /* write */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
		case 20: /* writev */ \
			(e)->ptr = (e)->args[1]; \
			bpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[1]); \
			break; \
	}

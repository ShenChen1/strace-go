#define CAPTURE_ARGS_ENTER(id, e) switch(id) { \
		case 0: /* read */ \
			(e)->ptr = (e)->args[1]; \
			break; \
		case 1: /* write */ \
			(e)->ptr = (e)->args[1]; \
			e->probe_ret_enter = bpf_probe_read_user((e)->str_arg, 512, (void *)(e)->args[1]); \
			break; \
		case 2: /* open */ \
			(e)->ptr = (e)->args[0]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[0]); \
			break; \
		case 4: /* stat */ \
			(e)->ptr = (e)->args[0]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[0]); \
			break; \
		case 6: /* lstat */ \
			(e)->ptr = (e)->args[0]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[0]); \
			break; \
		case 7: /* poll */ \
			e->probe_ret_enter = bpf_probe_read_user((e)->str_arg, 512, (void *)(e)->args[0]); \
			break; \
		case 14: /* rt_sigprocmask */ \
			e->probe_ret_enter = bpf_probe_read_user((e)->str_arg, 8, (void *)(e)->args[1]); \
			break; \
		case 16: /* ioctl */ \
			e->probe_ret_enter = bpf_probe_read_user((e)->str_arg + 512, 128, (void *)(e)->args[2]); \
			break; \
		case 21: /* access */ \
			(e)->ptr = (e)->args[0]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[0]); \
			break; \
		case 23: /* select */ \
			e->probe_ret_enter = bpf_probe_read_user((e)->str_arg, 128, (void *)(e)->args[1]); \
			e->probe_ret_enter = bpf_probe_read_user((e)->str_arg + 128, 128, (void *)(e)->args[2]); \
			e->probe_ret_enter = bpf_probe_read_user((e)->str_arg + 256, 128, (void *)(e)->args[3]); \
			break; \
		case 35: /* nanosleep */ \
			(e)->ptr = (e)->args[0]; \
			e->probe_ret_enter = bpf_probe_read_user((e)->str_arg, 16, (void *)(e)->args[0]); \
			break; \
		case 42: /* connect */ \
			(e)->ptr = (e)->args[1]; \
			e->probe_ret_enter = bpf_probe_read_user((e)->str_arg + 512, 256, (void *)(e)->args[1]); \
			break; \
		case 43: /* accept */ \
			(e)->ptr = (e)->args[1]; \
			e->probe_ret_enter = bpf_probe_read_user((e)->str_arg + 768, 4, (void *)(e)->args[2]); \
			break; \
		case 44: /* sendto */ \
			(e)->ptr = (e)->args[1]; \
			e->probe_ret_enter = bpf_probe_read_user((e)->str_arg, 512, (void *)(e)->args[1]); \
			break; \
		case 49: /* bind */ \
			(e)->ptr = (e)->args[1]; \
			e->probe_ret_enter = bpf_probe_read_user((e)->str_arg + 512, 256, (void *)(e)->args[1]); \
			break; \
		case 76: /* truncate */ \
			(e)->ptr = (e)->args[0]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[0]); \
			break; \
		case 80: /* chdir */ \
			(e)->ptr = (e)->args[0]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[0]); \
			break; \
		case 82: /* rename */ \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[0]); \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg + 1024, 512, (void *)(e)->args[1]); \
			break; \
		case 83: /* mkdir */ \
			(e)->ptr = (e)->args[0]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[0]); \
			break; \
		case 84: /* rmdir */ \
			(e)->ptr = (e)->args[0]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[0]); \
			break; \
		case 85: /* creat */ \
			(e)->ptr = (e)->args[0]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[0]); \
			break; \
		case 87: /* unlink */ \
			(e)->ptr = (e)->args[0]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[0]); \
			break; \
		case 89: /* readlink */ \
			(e)->ptr = (e)->args[0]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[0]); \
			break; \
		case 90: /* chmod */ \
			(e)->ptr = (e)->args[0]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[0]); \
			break; \
		case 92: /* chown */ \
			(e)->ptr = (e)->args[0]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[0]); \
			break; \
		case 94: /* lchown */ \
			(e)->ptr = (e)->args[0]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[0]); \
			break; \
		case 158: /* arch_prctl */ \
			(e)->ptr = (e)->args[1]; \
			break; \
		case 159: /* adjtimex */ \
			e->probe_ret_enter = bpf_probe_read_user((e)->str_arg + 512, 256, (void *)(e)->args[0]); \
			break; \
		case 161: /* chroot */ \
			(e)->ptr = (e)->args[0]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[0]); \
			break; \
		case 230: /* clock_nanosleep */ \
			(e)->ptr = (e)->args[2]; \
			e->probe_ret_enter = bpf_probe_read_user((e)->str_arg, 16, (void *)(e)->args[2]); \
			break; \
		case 233: /* epoll_ctl */ \
			e->probe_ret_enter = bpf_probe_read_user((e)->str_arg, 12, (void *)(e)->args[3]); \
			break; \
		case 257: /* openat */ \
			(e)->ptr = (e)->args[1]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[1]); \
			break; \
		case 258: /* mkdirat */ \
			(e)->ptr = (e)->args[1]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[1]); \
			break; \
		case 260: /* fchownat */ \
			(e)->ptr = (e)->args[1]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[1]); \
			break; \
		case 262: /* newfstatat */ \
			(e)->ptr = (e)->args[1]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[1]); \
			break; \
		case 263: /* unlinkat */ \
			(e)->ptr = (e)->args[1]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[1]); \
			break; \
		case 264: /* renameat */ \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[1]); \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg + 1024, 512, (void *)(e)->args[3]); \
			break; \
		case 265: /* linkat */ \
			(e)->ptr = (e)->args[1]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[1]); \
			break; \
		case 266: /* symlinkat */ \
			(e)->ptr = (e)->args[1]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[1]); \
			break; \
		case 267: /* readlinkat */ \
			(e)->ptr = (e)->args[1]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[1]); \
			break; \
		case 268: /* fchmodat */ \
			(e)->ptr = (e)->args[1]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[1]); \
			break; \
		case 269: /* faccessat */ \
			(e)->ptr = (e)->args[1]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[1]); \
			break; \
		case 270: /* pselect6 */ \
			e->probe_ret_enter = bpf_probe_read_user((e)->str_arg, 128, (void *)(e)->args[1]); \
			e->probe_ret_enter = bpf_probe_read_user((e)->str_arg + 128, 128, (void *)(e)->args[2]); \
			e->probe_ret_enter = bpf_probe_read_user((e)->str_arg + 256, 128, (void *)(e)->args[3]); \
			break; \
		case 271: /* ppoll */ \
			e->probe_ret_enter = bpf_probe_read_user((e)->str_arg, 512, (void *)(e)->args[0]); \
			break; \
		case 288: /* accept4 */ \
			(e)->ptr = (e)->args[1]; \
			e->probe_ret_enter = bpf_probe_read_user((e)->str_arg + 768, 4, (void *)(e)->args[2]); \
			break; \
		case 316: /* renameat2 */ \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[1]); \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg + 1024, 512, (void *)(e)->args[3]); \
			break; \
	}
#define CAPTURE_ARGS_EXIT(id, e) switch(id) { \
		case 0: /* read */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg, 512, (void *)(e)->args[1]); \
			break; \
		case 2: /* open */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 256, 144, (void *)(e)->args[1]); \
			break; \
		case 4: /* stat */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 256, 144, (void *)(e)->args[1]); \
			break; \
		case 5: /* fstat */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 256, 144, (void *)(e)->args[1]); \
			break; \
		case 6: /* lstat */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 256, 144, (void *)(e)->args[1]); \
			break; \
		case 7: /* poll */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg, 512, (void *)(e)->args[0]); \
			break; \
		case 16: /* ioctl */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 512, 128, (void *)(e)->args[2]); \
			break; \
		case 21: /* access */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 256, 144, (void *)(e)->args[1]); \
			break; \
		case 23: /* select */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg, 128, (void *)(e)->args[1]); \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 128, 128, (void *)(e)->args[2]); \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 256, 128, (void *)(e)->args[3]); \
			break; \
		case 43: /* accept */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 512, 256, (void *)(e)->args[1]); \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 772, 4, (void *)(e)->args[2]); \
			break; \
		case 45: /* recvfrom */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg, 512, (void *)(e)->args[1]); \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 512, 256, (void *)(e)->args[4]); \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 772, 4, (void *)(e)->args[5]); \
			break; \
		case 51: /* getsockname */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 512, 256, (void *)(e)->args[1]); \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 772, 4, (void *)(e)->args[2]); \
			break; \
		case 52: /* getpeername */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 512, 256, (void *)(e)->args[1]); \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 772, 4, (void *)(e)->args[2]); \
			break; \
		case 76: /* truncate */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 256, 144, (void *)(e)->args[1]); \
			break; \
		case 80: /* chdir */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 256, 144, (void *)(e)->args[1]); \
			break; \
		case 83: /* mkdir */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 256, 144, (void *)(e)->args[1]); \
			break; \
		case 84: /* rmdir */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 256, 144, (void *)(e)->args[1]); \
			break; \
		case 85: /* creat */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 256, 144, (void *)(e)->args[1]); \
			break; \
		case 87: /* unlink */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 256, 144, (void *)(e)->args[1]); \
			break; \
		case 89: /* readlink */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 256, 144, (void *)(e)->args[1]); \
			break; \
		case 90: /* chmod */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 256, 144, (void *)(e)->args[1]); \
			break; \
		case 92: /* chown */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 256, 144, (void *)(e)->args[1]); \
			break; \
		case 94: /* lchown */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 256, 144, (void *)(e)->args[1]); \
			break; \
		case 96: /* gettimeofday */ \
			(e)->ptr = (e)->args[0]; \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg, 16, (void *)(e)->args[0]); \
			break; \
		case 158: /* arch_prctl */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 512, 8, (void *)(e)->args[1]); \
			break; \
		case 159: /* adjtimex */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 512, 256, (void *)(e)->args[0]); \
			break; \
		case 161: /* chroot */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 256, 144, (void *)(e)->args[1]); \
			break; \
		case 217: /* getdents64 */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg, 512, (void *)(e)->args[1]); \
			break; \
		case 228: /* clock_gettime */ \
			(e)->ptr = (e)->args[1]; \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg, 16, (void *)(e)->args[1]); \
			break; \
		case 232: /* epoll_wait */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg, 512, (void *)(e)->args[1]); \
			break; \
		case 257: /* openat */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 256, 144, (void *)(e)->args[2]); \
			break; \
		case 258: /* mkdirat */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 256, 144, (void *)(e)->args[2]); \
			break; \
		case 260: /* fchownat */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 256, 144, (void *)(e)->args[2]); \
			break; \
		case 262: /* newfstatat */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 256, 144, (void *)(e)->args[2]); \
			break; \
		case 263: /* unlinkat */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 256, 144, (void *)(e)->args[2]); \
			break; \
		case 265: /* linkat */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 256, 144, (void *)(e)->args[2]); \
			break; \
		case 266: /* symlinkat */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 256, 144, (void *)(e)->args[2]); \
			break; \
		case 267: /* readlinkat */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 256, 144, (void *)(e)->args[2]); \
			break; \
		case 268: /* fchmodat */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 256, 144, (void *)(e)->args[2]); \
			break; \
		case 269: /* faccessat */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 256, 144, (void *)(e)->args[2]); \
			break; \
		case 270: /* pselect6 */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg, 128, (void *)(e)->args[1]); \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 128, 128, (void *)(e)->args[2]); \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 256, 128, (void *)(e)->args[3]); \
			break; \
		case 271: /* ppoll */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg, 512, (void *)(e)->args[0]); \
			break; \
		case 281: /* epoll_pwait */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg, 512, (void *)(e)->args[1]); \
			break; \
		case 288: /* accept4 */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 512, 256, (void *)(e)->args[1]); \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 772, 4, (void *)(e)->args[2]); \
			break; \
	}

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
		case 5: /* fstat */ \
			(e)->ptr = (e)->args[1]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[1]); \
			break; \
		case 6: /* lstat */ \
			(e)->ptr = (e)->args[0]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[0]); \
			break; \
		case 7: /* poll */ \
			bpf_probe_read_user((e)->str_arg, 512, (void *)(e)->args[0]); \
			break; \
		case 16: /* ioctl */ \
			e->probe_ret_enter = bpf_probe_read_user((e)->str_arg + 512, 128, (void *)(e)->args[2]); \
			break; \
		case 21: /* access */ \
			(e)->ptr = (e)->args[0]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[0]); \
			break; \
		case 23: /* select */ \
			bpf_probe_read_user((e)->str_arg, 128, (void *)(e)->args[1]); \
			bpf_probe_read_user((e)->str_arg + 128, 128, (void *)(e)->args[2]); \
			bpf_probe_read_user((e)->str_arg + 256, 128, (void *)(e)->args[3]); \
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
		case 45: /* recvfrom */ \
			(e)->ptr = (e)->args[1]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[1]); \
			break; \
		case 49: /* bind */ \
			(e)->ptr = (e)->args[1]; \
			e->probe_ret_enter = bpf_probe_read_user((e)->str_arg + 512, 256, (void *)(e)->args[1]); \
			break; \
		case 51: /* getsockname */ \
			(e)->ptr = (e)->args[1]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[1]); \
			break; \
		case 52: /* getpeername */ \
			(e)->ptr = (e)->args[1]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[1]); \
			break; \
		case 79: /* rmdir */ \
			(e)->ptr = (e)->args[0]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[0]); \
			break; \
		case 80: /* chdir */ \
			(e)->ptr = (e)->args[0]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[0]); \
			break; \
		case 82: /* rename */ \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[0]); \
			bpf_probe_read_user_str((e)->str_arg + 1024, 512, (void *)(e)->args[1]); \
			break; \
		case 83: /* mkdir */ \
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
		case 159: /* adjtimex */ \
			bpf_probe_read_user((e)->str_arg + 512, 256, (void *)(e)->args[0]); \
			break; \
		case 161: /* chroot */ \
			(e)->ptr = (e)->args[0]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[0]); \
			break; \
		case 232: /* epoll_wait */ \
			(e)->ptr = (e)->args[1]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[1]); \
			break; \
		case 233: /* epoll_ctl */ \
			bpf_probe_read_user((e)->str_arg, 12, (void *)(e)->args[3]); \
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
			bpf_probe_read_user_str((e)->str_arg + 1024, 512, (void *)(e)->args[3]); \
			break; \
		case 266: /* readlinkat */ \
			(e)->ptr = (e)->args[1]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[1]); \
			break; \
		case 267: /* chmodat */ \
			(e)->ptr = (e)->args[1]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[1]); \
			break; \
		case 269: /* faccessat */ \
			(e)->ptr = (e)->args[1]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[1]); \
			break; \
		case 270: /* pselect6 */ \
			bpf_probe_read_user((e)->str_arg, 128, (void *)(e)->args[1]); \
			bpf_probe_read_user((e)->str_arg + 128, 128, (void *)(e)->args[2]); \
			bpf_probe_read_user((e)->str_arg + 256, 128, (void *)(e)->args[3]); \
			break; \
		case 271: /* ppoll */ \
			bpf_probe_read_user((e)->str_arg, 512, (void *)(e)->args[0]); \
			break; \
		case 281: /* epoll_pwait */ \
			(e)->ptr = (e)->args[1]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[1]); \
			break; \
		case 288: /* accept4 */ \
			(e)->ptr = (e)->args[1]; \
			e->probe_ret_enter = bpf_probe_read_user((e)->str_arg + 768, 4, (void *)(e)->args[2]); \
			break; \
		case 316: /* renameat2 */ \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[1]); \
			bpf_probe_read_user_str((e)->str_arg + 1024, 512, (void *)(e)->args[3]); \
			break; \
		case 439: /* faccessat2 */ \
			(e)->ptr = (e)->args[1]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[1]); \
			break; \
		case 441: /* epoll_pwait2 */ \
			(e)->ptr = (e)->args[1]; \
			e->probe_ret_enter = bpf_probe_read_user_str((e)->str_arg, 512, (void *)(e)->args[1]); \
			break; \
	}
#define CAPTURE_ARGS_EXIT(id, e) switch(id) { \
		case 0: /* read */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg, 512, (void *)(e)->args[1]); \
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
			bpf_probe_read_user((e)->str_arg, 512, (void *)(e)->args[0]); \
			break; \
		case 16: /* ioctl */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 512, 128, (void *)(e)->args[2]); \
			break; \
		case 23: /* select */ \
			bpf_probe_read_user((e)->str_arg, 128, (void *)(e)->args[1]); \
			bpf_probe_read_user((e)->str_arg + 128, 128, (void *)(e)->args[2]); \
			bpf_probe_read_user((e)->str_arg + 256, 128, (void *)(e)->args[3]); \
			break; \
		case 43: /* accept */ \
			bpf_probe_read_user((e)->str_arg + 512, 256, (void *)(e)->args[1]); \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 772, 4, (void *)(e)->args[2]); \
			break; \
		case 45: /* recvfrom */ \
			bpf_probe_read_user((e)->str_arg, 512, (void *)(e)->args[1]); \
			bpf_probe_read_user((e)->str_arg + 512, 256, (void *)(e)->args[4]); \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 772, 4, (void *)(e)->args[5]); \
			break; \
		case 51: /* getsockname */ \
			bpf_probe_read_user((e)->str_arg + 512, 256, (void *)(e)->args[1]); \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 772, 4, (void *)(e)->args[2]); \
			break; \
		case 52: /* getpeername */ \
			bpf_probe_read_user((e)->str_arg + 512, 256, (void *)(e)->args[1]); \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 772, 4, (void *)(e)->args[2]); \
			break; \
		case 159: /* adjtimex */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 512, 256, (void *)(e)->args[0]); \
			break; \
		case 232: /* epoll_wait */ \
			bpf_probe_read_user((e)->str_arg, 512, (void *)(e)->args[1]); \
			break; \
		case 262: /* newfstatat */ \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 256, 144, (void *)(e)->args[2]); \
			break; \
		case 270: /* pselect6 */ \
			bpf_probe_read_user((e)->str_arg, 128, (void *)(e)->args[1]); \
			bpf_probe_read_user((e)->str_arg + 128, 128, (void *)(e)->args[2]); \
			bpf_probe_read_user((e)->str_arg + 256, 128, (void *)(e)->args[3]); \
			break; \
		case 271: /* ppoll */ \
			bpf_probe_read_user((e)->str_arg, 512, (void *)(e)->args[0]); \
			break; \
		case 281: /* epoll_pwait */ \
			bpf_probe_read_user((e)->str_arg, 512, (void *)(e)->args[1]); \
			break; \
		case 288: /* accept4 */ \
			bpf_probe_read_user((e)->str_arg + 512, 256, (void *)(e)->args[1]); \
			e->probe_ret_exit = bpf_probe_read_user((e)->str_arg + 772, 4, (void *)(e)->args[2]); \
			break; \
	}

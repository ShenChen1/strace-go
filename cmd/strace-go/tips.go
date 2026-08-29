package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"time"

	"strace-go/pkg/cli"
)

const traceTipWidth = 44

var traceTipStrauss = []string{
	"",
	"     ____",
	"    /    \\",
	"   |-. .-.|",
	"   (_@)(_@)",
	"   .---_  \\",
	"  /..   \\_/",
	"  |__.-^ /",
	"      }  |",
	"     |   [",
	"     [  ]",
	"    ]   |",
	"    |   [",
	"    [  ]",
	"   /   |        __",
	"  \\|   |/     _/ /_",
	" \\ |   |//___/__/__/_",
	"\\\\  \\ /  //    -____/_",
	"//   \"   \\\\      \\___.-",
	" //     \\\\  __.----._/_",
	"/ '/|||\\` .-         __>",
	"[        /         __.-",
	"[        [           }",
	"\\        \\          /",
	" \"-._____ \\.____.--\"",
	"    |  | |  |",
	"    |  | |  |",
	"    |  | |  |",
	"    |  | |  |",
	"    {  } {  }",
	"    |  | |  |",
	"    |  | |  |",
	"    |  | |  |",
	"    /  { |  |",
	" .-\"   / [   -._",
	"/___/ /   \\ \\___\"-.",
	"    -\"     \"-",
}

var traceTips = [][]string{
	{
		"strace has an extensive manual page",
		"that covers all the possible options",
		"and contains several useful invocation",
		"examples.",
	},
	{
		"Timestamps from -r, -t, and -T can use",
		"nanosecond precision through their long",
		"option forms with the ns precision.",
	},
	{
		"The -E/--env option can add, replace, or",
		"remove variables in the traced command's",
		"environment.",
	},
	{
		"Use -A/--output-append-mode with -o to",
		"preserve an existing trace output file.",
	},
	{
		"Syscall and signal filters accept names,",
		"numbers, classes, and negated sets.",
	},
	{
		"If trace lifecycle messages are too noisy,",
		"use -q, -qq, or -qqq to suppress them.",
	},
	{
		"Use -y/--decode-fds=path to print paths",
		"associated with file descriptor arguments.",
	},
	{
		"The -U/--summary-columns option controls",
		"which columns appear in -c and -C output.",
	},
	{
		"Use --strings-in-hex=non-ascii-chars to",
		"render individual non-ASCII escapes in hex.",
	},
	{
		"The -n/--syscall-number option prints each",
		"system call number beside its name.",
	},
}

var traceTipRight = []string{" \\   ", " |   ", " \\   ", "  \\  ", "  _\\ ", " /   ", " |   "}

func renderTraceTip(out io.Writer, mode string, id int) error {
	if mode == "" || mode == cli.TipsModeNone {
		return nil
	}
	if out == nil {
		return fmt.Errorf("tip output is nil")
	}
	tip := traceTips[normalizedTraceTipID(id)]
	var rendered bytes.Buffer
	fmt.Fprintf(&rendered, "  ______________________________________________    %s\n", traceTipStrauss[1])
	fmt.Fprintf(&rendered, " / %-*s%s%s\n", traceTipWidth, "", traceTipRight[0], traceTipStrauss[2])

	line := 0
	for line < 14 && (line < 6 || traceTipLine(tip, line) != "") {
		right := traceTipRight[min(line+1, len(traceTipRight)-1)]
		fmt.Fprintf(&rendered, " | %-*s%s%s\n", traceTipWidth, traceTipLine(tip, line), right, traceTipStrauss[3+line])
		line++
	}
	fmt.Fprintf(&rendered, " \\______________________________________________/   %s\n", traceTipStrauss[3+line])
	writeTraceTipTail(&rendered, mode, 4+line)
	_, err := out.Write(rendered.Bytes())
	return err
}

func normalizedTraceTipID(id int) int {
	if id == cli.TipsIDRandom {
		id = int(time.Now().UnixNano() ^ int64(os.Getpid()))
	}
	if id < 0 {
		id = -id
	}
	return id % len(traceTips)
}

func traceTipLine(tip []string, line int) string {
	if line < len(tip) {
		return tip[line]
	}
	return ""
}

func writeTraceTipTail(out *bytes.Buffer, mode string, start int) {
	end := min(start+1, len(traceTipStrauss))
	if mode == cli.TipsModeFull {
		end = len(traceTipStrauss)
	}
	for index := start; index < end; index++ {
		fmt.Fprintf(out, "%52s%s\n", "", traceTipStrauss[index])
	}
}

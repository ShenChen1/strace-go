import os

with open('/opt/strace-go/pkg/handler/bpf_progs_ext.go', 'r') as f:
    lines = f.readlines()

new_file_lines = [
    "package handler\n\n",
    "import (\n",
    "\t\"fmt\"\n",
    "\t\"strings\"\n\n",
    "\t\"strace-go/pkg/meta\"\n",
    ")\n\n"
]

bpf_lines = []
for i, line in enumerate(lines):
    if i < 9: # skip package and import
        bpf_lines.append(line)
        continue
    
    line_num = i + 1
    
    if (459 <= line_num <= 506):
        new_file_lines.append(line)
    else:
        bpf_lines.append(line)

with open('/opt/strace-go/pkg/handler/bpf_progs_ext2.go', 'w') as f:
    f.writelines(new_file_lines)

with open('/opt/strace-go/pkg/handler/bpf_progs_ext.go', 'w') as f:
    f.writelines(bpf_lines)

print("Done bpf_progs_ext.go")

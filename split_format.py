import os

with open('/opt/strace-go/pkg/format/format.go', 'r') as f:
    lines = f.readlines()

new_file_lines = [
    "package format\n\n",
    "import (\n",
    "\t\"encoding/binary\"\n",
    "\t\"fmt\"\n",
    "\t\"strings\"\n",
    "\t\"time\"\n\n",
    "\t\"strace-go/pkg/meta\"\n",
    ")\n\n"
]

format_lines = []
for i, line in enumerate(lines):
    if i < 11: # skip package and import
        format_lines.append(line)
        continue
    
    # we want to extract:
    # Timespec (24-30) -> index 23-29
    # Timeval (32-38)
    # Pollfds (40-59)
    # EpollEvents (61-79)
    # EpollEvent (81-91)
    # IoEvents (93-108)
    # Stat (110-142)
    # Timex (144-161)
    # Utimes (216-245)
    # Sockaddr (247-282)
    
    line_num = i + 1
    
    if (24 <= line_num <= 161) or (216 <= line_num <= 245) or (247 <= line_num <= 282) or (333 <= line_num <= 343) or (499 <= line_num <= 553):
        new_file_lines.append(line)
    else:
        format_lines.append(line)

with open('/opt/strace-go/pkg/format/format_socket.go', 'w') as f:
    f.writelines(new_file_lines)

with open('/opt/strace-go/pkg/format/format.go', 'w') as f:
    f.writelines(format_lines)

print("Done format.go")

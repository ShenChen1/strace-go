import os

with open('/opt/strace-go/cmd/strace-go/event.go', 'r') as f:
    lines = f.readlines()

new_file_lines = [
    "package main\n\n",
    "import (\n",
    "\t\"encoding/binary\"\n",
    "\t\"fmt\"\n",
    "\t\"os\"\n",
    "\t\"regexp\"\n",
    "\t\"strings\"\n\n",
    "\t\"strace-go/pkg/cli\"\n",
    "\t\"strace-go/pkg/event\"\n",
    "\t\"strace-go/pkg/handler\"\n",
    "\t\"strace-go/pkg/meta\"\n",
    ")\n\n"
]

event_lines = []
for i, line in enumerate(lines):
    if i < 18: # skip package and import
        event_lines.append(line)
        continue
    
    line_num = i + 1
    
    if (170 <= line_num <= 277) or (279 <= line_num <= 302) or (491 <= line_num <= 504):
        new_file_lines.append(line)
    else:
        event_lines.append(line)

with open('/opt/strace-go/cmd/strace-go/event_utils.go', 'w') as f:
    f.writelines(new_file_lines)

with open('/opt/strace-go/cmd/strace-go/event.go', 'w') as f:
    f.writelines(event_lines)

print("Done event.go")

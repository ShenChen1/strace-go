import os

with open('/opt/strace-go/pkg/handler/decode_scalar.go', 'r') as f:
    lines = f.readlines()

new_file_lines = [
    "package handler\n\n",
    "import (\n",
    "\t\"fmt\"\n",
    "\t\"os\"\n",
    "\t\"strings\"\n",
    ")\n\n"
]

scalar_lines = []
for i, line in enumerate(lines):
    if i < 14: # skip package and import
        scalar_lines.append(line)
        continue
    
    line_num = i + 1
    
    if (464 <= line_num <= 511):
        new_file_lines.append(line)
    else:
        scalar_lines.append(line)

with open('/opt/strace-go/pkg/handler/decode_scalar_utils.go', 'w') as f:
    f.writelines(new_file_lines)

with open('/opt/strace-go/pkg/handler/decode_scalar.go', 'w') as f:
    f.writelines(scalar_lines)

print("Done decode_scalar.go")

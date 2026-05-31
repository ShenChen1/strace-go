import re

with open('/opt/strace-go/cmd/strace-go/event.go', 'r') as f:
    content = f.read()

content = content.replace('\t"encoding/binary"\n', '')
content = content.replace('\t"os"\n', '')
content = content.replace('\t"regexp"\n', '')
content = content.replace('\t"strace-go/pkg/event"\n', '')

with open('/opt/strace-go/cmd/strace-go/event.go', 'w') as f:
    f.write(content)


import re

with open('/opt/strace-go/pkg/format/format.go', 'r') as f:
    content = f.read()

content = content.replace('\t"time"\n', '')
content = content.replace('\t"strace-go/pkg/meta"\n', '')

with open('/opt/strace-go/pkg/format/format.go', 'w') as f:
    f.write(content)


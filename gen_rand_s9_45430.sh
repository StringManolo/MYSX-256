#!/usr/bin/env bash

python3 -c "
import random
rng = random.Random(9)
for i in range(45431):
    seq = list(range(31)); rng.shuffle(seq)
cal = [(seq[r%31]+1) for r in range(128)]
open('CALENDAR_v02.txt','w').write('MYSX_ROT_CAL=' + ','.join(str(x) for x in cal[:31]) + '\n')
print('OK')
"

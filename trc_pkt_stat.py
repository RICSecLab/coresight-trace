#!/usr/bin/env python3

import sys

ID_OFFSET = 0x10
ID_MAX = 0x2f

TRACE_CPU = 1

def main():
    if len(sys.argv) < 2:
        print('Usage: {} LIST'.format(sys.argv[0]))
        return -1
    
    count = [0 for i in range(ID_OFFSET, ID_MAX+1)]
    with open(sys.argv[1], 'r') as fp:
        for line in fp:
            pos = line.find('ID:')
            if pos != -1:
                idx = int(line[pos+3:pos+5], 16)
                count[idx - ID_OFFSET] += 1

    if count[TRACE_CPU] < 10: # TODO: Correct threshold to be defined
        print("!!! No meaningful trace captured: CPU #{}: {}".format(TRACE_CPU, count[TRACE_CPU]))
        return 1

    return 0

if __name__ == '__main__':
    sys.exit(main())

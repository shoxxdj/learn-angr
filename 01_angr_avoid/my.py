#identique à 00

import angr
import sys

find = 0x000012dd+0x400000
avoid = 0x00001254+0x400000

p = angr.Project('./res')
state = p.factory.entry_state()

s = p.factory.simulation_manager(state)
s.explore(find=find,avoid=avoid)

print(s.found[0].posix.dumps(sys.stdin.fileno()))

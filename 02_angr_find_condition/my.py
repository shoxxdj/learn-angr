#Pour celui ci on ne s'embête pas à chercher les adresses de find et avoid mais on se base sur l'output du programme
#on fait donc 2 fonctions is_success cherche si la string 

import angr
import sys

#find = 0x00006332+0x400000
#avoid = 0x00001254+0x400000

p = angr.Project('./res')
state = p.factory.entry_state()
s = p.factory.simulation_manager(state)

def is_success(state):
 stdout_output = state.posix.dumps(sys.stdout.fileno())
 if('Good Job.' in str(stdout_output)):
  return True
 else:
  return False

def is_wrong(state):
 stdout_output = state.posix.dumps(sys.stdout.fileno())
 if('Try again.' in str(stdout_output)):
  return True
 else:
  return False
 
s.explore(find=is_success,avoid=is_wrong)

print(s.found[0].posix.dumps(sys.stdin.fileno()))

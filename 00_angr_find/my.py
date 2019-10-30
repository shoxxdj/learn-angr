import angr
import sys

find = 0x1350+0x400000 #adresse de win + pie
avoid = 0x133c+0x400000 #adresse de loose + pie 

p = angr.Project('./res') #chargement du binaire
state = p.factory.entry_state() #state par défaut 

s = p.factory.simulation_manager(state)
s.explore(find=find,avoid=avoid) #on cherche à arrvier à find



print(s.found[0].posix.dumps(sys.stdin.fileno())) #permet d'obtenir la dernière string passée en stdin par angr

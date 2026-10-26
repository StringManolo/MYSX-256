"""emp_check.py -- empirical correlation of a saved beam trail vs the real cipher (fixed key).
usage: python3 emp_check.py beam.json OFFSET R LOG2_N KEYSEED   (key = rand_key(KEYSEED), same as hull_bidir --keys)"""
import json, sys, time, os
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'cryptanalysis', 'models', 'linear'))
import mysx_linear_model as ML
fn, off, R, logN, keyseed = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
d=json.load(open(fn)); r=[x for x in d["results"] if x["offset"]==off][0]
path=[int(h,16) for h in r["paths"][str(R)]]; first=r.get("first_round",{}).get(str(R), off)
tup=lambda x: tuple((x>>(32*i))&0xFFFFFFFF for i in range(8))
key=ML.rand_key(keyseed); rks=ML.key_schedule(key)[0]
t=time.time()
c,s=ML.empirical_corr(tup(path[0]), tup(path[R]), rks, R, N=1<<logN, seed=11, r0=first)
print("%s off=%d R=%d key=%d N=2^%d: corr=%+.4e  sigma=%.2e  z-scores: vs0=%.1f  (%.0fs)"%(fn,off,R,keyseed,logN,c,s,c/s,time.time()-t), flush=True)

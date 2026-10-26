import math, sys
from fractions import Fraction
import hull_bidir as H
import mysx_linear_model as ML

def to_int(m): return sum(w << (32*i) for i,w in enumerate(m))
bad=0; checked=0
for (r0,R,bit,T) in ((12,10,174,6),(12,11,174,6),(27,10,146,6),(12,12,174,6)):
    for kseed in (1000,1001):
        key=ML.rand_key(kseed); rks=ML.key_schedule(key)[0]
        RKL=[H.rk_int(rk) for rk in rks]
        m0=tuple((1<<(bit-32*i)) if 32*i<=bit<32*i+32 else 0 for i in range(8))
        vec=ML.propagate(m0,R,rks=rks,r0=r0,T=T)
        top=sorted(vec.items(), key=lambda kv:-abs(kv[1]))[:6]
        for mv,val in top:
            v=to_int(mv)
            res=H.hull(to_int(m0),v,r0,R,T,RKL,True,5_000_000,verbose=False)
            mine=sum(Fraction(c,1<<w) for w,c in res.items())
            ref=Fraction(val, ML.SCALE)
            checked+=1
            if mine!=ref:
                bad+=1
                print("MISMATCH r0=%d R=%d key %d: model %s  mine %s  per-weight %s"%(r0,R,kseed,float(ref),float(mine),res))
print("checked",checked,"mismatches",bad)

# Streaming z_stream API vs the system zlib (python's zlib module): all containers,
# flush modes, odd chunk sizes, preset dictionaries, corruption.
import zlib, subprocess, sys, os, random
import tempfile
T=tempfile.mkdtemp(prefix='zx.',dir=os.environ.get('TMPDIR','.'))
tool=os.environ.get('ZSTREAM_TOOL','zig-out/bin/zstream_tool')
random.seed(7)
def run(*a):
    return subprocess.run([tool]+[str(x) for x in a],capture_output=True,timeout=60)
corpus={}
corpus['text']=(open('zstd/doc/zstd_manual.html','rb').read()+open('zstd/lib/zstd.h','rb').read())[:600000]
corpus['bin']=open(os.environ.get('ZSTREAM_BIN','zig-out/bin/nstd'),'rb').read()[:400000]
corpus['rand']=os.urandom(200000)
corpus['rle']=b'a'*300000
corpus['tiny']=b'hi'
corpus['empty']=b''
fails=0
def check(c, msg):
    global fails
    if not c: print("FAIL",msg); fails+=1
for name,data in corpus.items():
    open(f'{T}/in','wb').write(data)
    for wb,mode in ((15,'zlib'),(-15,'raw'),(31,'gzip'),(12,'zlib12')):
        for level in (1,6,9):
            for chunk,fe in ((1000,0),(65536,3),(7,5)):
                if len(data)>50000 and chunk==7: continue
                r=run('def',level,wb,chunk,fe,f'{T}/in',f'{T}/out')
                check(r.returncode==0,f"def rc={r.returncode} {name} {mode} L{level} c{chunk}")
                comp=open(f'{T}/out','rb').read()
                try:
                    back=zlib.decompress(comp, wb if wb>0 else wb) if wb!=31 else zlib.decompress(comp,31)
                except Exception as e:
                    check(False,f"python zlib rejects ours {name} {mode} L{level} c{chunk}: {e}"); continue
                check(back==data,f"python zlib mismatch {name} {mode} L{level} c{chunk}")
    # python-made streams through our inflate in odd chunk sizes
    for wb in (15,-15,31):
        co=zlib.compressobj(6,zlib.DEFLATED,wb)
        comp=co.compress(data[:len(data)//2])+co.flush(zlib.Z_SYNC_FLUSH)+co.compress(data[len(data)//2:])+co.flush()
        open(f'{T}/pin','wb').write(comp)
        for ic,oc in ((1,1),(13,5),(4096,100),(100000,100000)):
            if ic<13 and len(comp)>20000: continue
            r=run('inf',wb,ic,oc,f'{T}/pin',f'{T}/pout')
            check(r.returncode==0,f"inf rc={r.returncode} {name} wb{wb} {ic}/{oc}: {r.stderr[:80]}")
            check(open(f'{T}/pout','rb').read()==data,f"inf mismatch {name} wb{wb} {ic}/{oc}")
# auto-detect
for wb in (47,):
    for src in (zlib.compress(corpus['text'][:100000]), None):
        if src is None:
            co=zlib.compressobj(6,zlib.DEFLATED,31); src=co.compress(corpus['text'][:100000])+co.flush()
        open(f'{T}/pin','wb').write(src)
        r=run('inf',wb,500,500,f'{T}/pin',f'{T}/pout')
        check(r.returncode==0 and open(f'{T}/pout','rb').read()==corpus['text'][:100000],"auto-detect inflate")
# preset dictionary both ways
dic=corpus['text'][1000:9000]; open(f'{T}/dict','wb').write(dic)
sample=corpus['text'][3000:5000]; open(f'{T}/in','wb').write(sample)
r=run('def',6,15,512,0,f'{T}/in',f'{T}/out',f'{T}/dict'); check(r.returncode==0,"def dict")
d=zlib.decompressobj(15,zdict=dic); check(d.decompress(open(f'{T}/out','rb').read())==sample,"python decodes our FDICT stream")
co=zlib.compressobj(6,zlib.DEFLATED,15,zdict=dic); comp=co.compress(sample)+co.flush(); open(f'{T}/pin','wb').write(comp)
r=run('inf',15,300,300,f'{T}/pin',f'{T}/pout',f'{T}/dict'); check(r.returncode==0 and open(f'{T}/pout','rb').read()==sample,"we decode python FDICT stream")
# corruption must not crash or hang
good=zlib.compress(corpus['text'][:50000])
for k in range(30):
    b=bytearray(good); b[random.randrange(len(b))]^=1<<random.randrange(8)
    open(f'{T}/pin','wb').write(bytes(b))
    r=subprocess.run([tool,'inf',15,100,100,f'{T}/pin',f'{T}/pout'],capture_output=True,timeout=60) if False else subprocess.run([tool,'inf','15','100','100',f'{T}/pin',f'{T}/pout'],capture_output=True,timeout=60)
    check(r.returncode in (0,5,9),f"corrupt stream rc={r.returncode}")
import shutil; shutil.rmtree(T, ignore_errors=True)
print("zstream interop:", "all pass" if fails==0 else f"{fails} FAILURES")
sys.exit(1 if fails else 0)

from __future__ import annotations
import hashlib,json,struct,sys
from pathlib import Path
PREFIX=struct.Struct('<8sIQ'); MAGIC=b'EPTBv004'
DEFAULT={'max_tensor_words':1<<30,'max_block_words':1<<26,'max_block_bytes':1<<31,'max_header_bytes':4<<20,'max_payload_bytes':64<<30,'max_stream_count':4096,'max_stream_decompressed_bytes':1<<30,'max_arena_bytes':2<<30}

def canonical(v): return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
def rebuild(meta,payload,magic=MAGIC):
 h=canonical(meta); body=PREFIX.pack(magic,len(h),len(payload))+h+payload; return body+hashlib.sha256(body).digest()
def classify(data,lim):
 if len(data)>lim['max_block_bytes']:return 'RESOURCE_MAX_BLOCK_BYTES'
 if len(data)<52:return 'FORMAT_TRUNCATED'
 magic,hl,pl=PREFIX.unpack(data[:20])
 if magic not in {b'EPTBv001',b'EPTBv002',b'EPTBv003',b'EPTBv004'}:return 'FORMAT_MAGIC'
 if hl>lim['max_header_bytes']:return 'RESOURCE_MAX_HEADER_BYTES'
 if pl>lim['max_payload_bytes']:return 'RESOURCE_MAX_PAYLOAD_BYTES'
 if 20+hl+pl+32!=len(data):return 'FORMAT_LENGTH'
 if hashlib.sha256(data[:-32]).digest()!=data[-32:]:return 'INTEGRITY_BLOCK_SHA256'
 try:m=json.loads(data[20:20+hl].decode('ascii'))
 except (UnicodeDecodeError,json.JSONDecodeError):return 'FORMAT_JSON'
 if not isinstance(m,dict):return 'FORMAT_JSON_ROOT'
 streams=m.get('streams')
 if not isinstance(streams,list):return 'FORMAT_STREAMS'
 if len(streams)>lim['max_stream_count']:return 'RESOURCE_MAX_STREAM_COUNT'
 wc=m.get('word_count')
 if not isinstance(wc,int) or isinstance(wc,bool) or wc<0:return 'FORMAT_WORD_COUNT'
 if wc>lim['max_tensor_words']:return 'RESOURCE_MAX_TENSOR_WORDS'
 if wc>lim['max_block_words']:return 'RESOURCE_MAX_BLOCK_WORDS'
 payload=data[20+hl:20+hl+pl]; occ=[]; names=set(); dt=0
 for d in streams:
  if not isinstance(d,dict):return 'FORMAT_DESCRIPTOR'
  name=d.get('name'); off=d.get('offset'); ln=d.get('length'); dig=d.get('sha256')
  if not isinstance(name,str) or not name or name in names:return 'FORMAT_STREAM_NAME'
  names.add(name)
  if not isinstance(off,int) or isinstance(off,bool) or not isinstance(ln,int) or isinstance(ln,bool):return 'FORMAT_DESCRIPTOR'
  if off<0 or ln<0 or off+ln>pl:return 'FORMAT_STREAM_BOUNDS'
  iv=(off,off+ln)
  if any(max(iv[0],a)<min(iv[1],b) for a,b in occ):return 'FORMAT_STREAM_OVERLAP'
  occ.append(iv)
  if not isinstance(dig,str) or hashlib.sha256(payload[off:off+ln]).hexdigest()!=dig:return 'INTEGRITY_STREAM_SHA256'
  dl=d.get('decoded_length')
  if dl is None:dl=ln if d.get('encoding','raw')=='raw' else 0
  if not isinstance(dl,int) or isinstance(dl,bool) or dl<0:return 'FORMAT_DECODED_LENGTH'
  if dl>lim['max_stream_decompressed_bytes']:return 'RESOURCE_MAX_STREAM_DECOMPRESSED_BYTES'
  dt+=dl
 if wc*2+dt>lim['max_arena_bytes']:return 'RESOURCE_MAX_ARENA_BYTES'
 if m.get('format')!='ExactProgressiveTensorBlock':return 'FORMAT_SEMANTIC_FORMAT'
 if not isinstance(m.get('version'),int) or m['version'] not in {1,2,3,4}:return 'FORMAT_SEMANTIC_VERSION'
 return 'OK'

def mk():
 payload=bytes(range(256)); s={'name':'raw_words','encoding':'raw','offset':0,'length':256,'decoded_length':256,'sha256':hashlib.sha256(payload).hexdigest()}; meta={'format':'ExactProgressiveTensorBlock','version':4,'word_count':128,'dtype':'bf16','shape':[128],'streams':[s]}; valid=rebuild(meta,payload); _,hl,pl=PREFIX.unpack(valid[:20]); cases=[]
 def add(id,b,exp,**ov):
  l=dict(DEFAULT);l.update(ov);got=classify(b,l);assert got==exp,(id,got,exp);cases.append({'id':id,'blob_hex':b.hex(),'limits':l,'expected':exp})
 add('ok',valid,'OK');add('limit_block_bytes',valid,'RESOURCE_MAX_BLOCK_BYTES',max_block_bytes=len(valid)-1);add('limit_header_bytes',valid,'RESOURCE_MAX_HEADER_BYTES',max_header_bytes=hl-1);add('limit_payload_bytes',valid,'RESOURCE_MAX_PAYLOAD_BYTES',max_payload_bytes=pl-1);add('limit_tensor_words',valid,'RESOURCE_MAX_TENSOR_WORDS',max_tensor_words=127);add('limit_block_words',valid,'RESOURCE_MAX_BLOCK_WORDS',max_block_words=127);add('limit_stream_decoded',valid,'RESOURCE_MAX_STREAM_DECOMPRESSED_BYTES',max_stream_decompressed_bytes=255);add('limit_arena',valid,'RESOURCE_MAX_ARENA_BYTES',max_arena_bytes=511)
 m2=dict(meta);m2['streams']=[dict(s,name='a',offset=0,length=1,decoded_length=1,sha256=hashlib.sha256(payload[:1]).hexdigest()),dict(s,name='b',offset=1,length=1,decoded_length=1,sha256=hashlib.sha256(payload[1:2]).hexdigest())];add('limit_stream_count',rebuild(m2,payload),'RESOURCE_MAX_STREAM_COUNT',max_stream_count=1)
 add('format_truncated',valid[:20],'FORMAT_TRUNCATED');b=bytearray(valid);b[:8]=b'BADMAGIC';add('format_magic',bytes(b),'FORMAT_MAGIC');b=bytearray(valid);struct.pack_into('<Q',b,12,pl+1);add('format_length',bytes(b),'FORMAT_LENGTH');b=bytearray(valid);b[-1]^=1;add('integrity_block',bytes(b),'INTEGRITY_BLOCK_SHA256')
 body=PREFIX.pack(MAGIC,1,0)+b'{';add('format_json',body+hashlib.sha256(body).digest(),'FORMAT_JSON');body=PREFIX.pack(MAGIC,2,0)+b'[]';add('format_json_root',body+hashlib.sha256(body).digest(),'FORMAT_JSON_ROOT')
 m=dict(meta);m.pop('streams');add('format_streams',rebuild(m,payload),'FORMAT_STREAMS');m=dict(meta);m['word_count']='x';add('format_word_count',rebuild(m,payload),'FORMAT_WORD_COUNT');m=dict(meta);m['streams']=[123];add('format_descriptor',rebuild(m,payload),'FORMAT_DESCRIPTOR');m=json.loads(json.dumps(meta));m['streams'][0]['decoded_length']='x';add('format_decoded_length',rebuild(m,payload),'FORMAT_DECODED_LENGTH');m=json.loads(json.dumps(meta));m['streams'][0]['name']='';add('format_stream_name',rebuild(m,payload),'FORMAT_STREAM_NAME');m=json.loads(json.dumps(meta));m['streams'][0]['length']=257;add('format_stream_bounds',rebuild(m,payload),'FORMAT_STREAM_BOUNDS')
 m=dict(meta);d0=dict(s,name='a',offset=0,length=8,decoded_length=8,sha256=hashlib.sha256(payload[:8]).hexdigest());d1=dict(d0,name='b',offset=4,sha256=hashlib.sha256(payload[4:12]).hexdigest());m['streams']=[d0,d1];add('format_stream_overlap',rebuild(m,payload),'FORMAT_STREAM_OVERLAP');m=json.loads(json.dumps(meta));m['streams'][0]['sha256']='0'*64;add('integrity_stream',rebuild(m,payload),'INTEGRITY_STREAM_SHA256');m=dict(meta);m['format']='Other';add('semantic_format',rebuild(m,payload),'FORMAT_SEMANTIC_FORMAT');m=dict(meta);m['version']=99;add('semantic_version',rebuild(m,payload),'FORMAT_SEMANTIC_VERSION')
 return {'format':'EPTBParserParityCorpus','version':'0.4.0','case_count':len(cases),'cases':cases}

if __name__=='__main__':
 out=Path(sys.argv[1]); report=Path(sys.argv[2]); d=mk(); out.write_text(json.dumps(d,indent=2,sort_keys=True)+'\n'); rows=[{'id':c['id'],'expected':c['expected'],'actual':classify(bytes.fromhex(c['blob_hex']),c['limits'])} for c in d['cases']]; r={'format':'EPTBPythonParserParity','version':'0.4.0','case_count':len(rows),'mismatch_count':sum(x['actual']!=x['expected'] for x in rows),'corpus_sha256':hashlib.sha256(out.read_bytes()).hexdigest(),'cases':rows};report.write_text(json.dumps(r,indent=2,sort_keys=True)+'\n');print(json.dumps({'case_count':r['case_count'],'mismatch_count':r['mismatch_count'],'corpus_sha256':r['corpus_sha256']},indent=2));raise SystemExit(0 if r['mismatch_count']==0 else 2)

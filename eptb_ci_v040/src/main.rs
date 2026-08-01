use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, env, fs};

#[derive(Clone, Debug, Deserialize)]
struct DecodeLimits {
    max_tensor_words: u64,
    max_block_words: u64,
    max_block_bytes: u64,
    max_header_bytes: u64,
    max_payload_bytes: u64,
    max_stream_count: u64,
    max_stream_decompressed_bytes: u64,
    max_arena_bytes: u64,
}

#[derive(Debug, Deserialize)]
struct Case { id: String, blob_hex: String, limits: DecodeLimits, expected: String }
#[derive(Debug, Deserialize)]
struct Corpus { cases: Vec<Case> }
#[derive(Debug, Serialize)]
struct Row { id: String, expected: String, actual: String, pass: bool }
#[derive(Debug, Serialize)]
struct Report { format: &'static str, version: &'static str, case_count: usize, mismatch_count: usize, cases: Vec<Row> }

fn le_u32(x: &[u8]) -> u32 { u32::from_le_bytes(x.try_into().unwrap()) }
fn le_u64(x: &[u8]) -> u64 { u64::from_le_bytes(x.try_into().unwrap()) }
fn hexval(c: u8) -> Option<u8> { match c { b'0'..=b'9'=>Some(c-b'0'), b'a'..=b'f'=>Some(c-b'a'+10), b'A'..=b'F'=>Some(c-b'A'+10), _=>None } }
fn decode_hex(s:&str)->Option<Vec<u8>> { let b=s.as_bytes(); if b.len()%2!=0{return None}; let mut out=Vec::with_capacity(b.len()/2); for i in (0..b.len()).step_by(2){out.push((hexval(b[i])?<<4)|hexval(b[i+1])?)} Some(out) }
fn is_nonnegative_u64(v: Option<&Value>) -> Option<u64> { v?.as_u64() }

fn classify(data: &[u8], lim: &DecodeLimits) -> &'static str {
    if data.len() as u64 > lim.max_block_bytes { return "RESOURCE_MAX_BLOCK_BYTES"; }
    if data.len() < 52 { return "FORMAT_TRUNCATED"; }
    let magic=&data[..8];
    if !matches!(magic, b"EPTBv001"|b"EPTBv002"|b"EPTBv003"|b"EPTBv004") { return "FORMAT_MAGIC"; }
    let hlen=le_u32(&data[8..12]) as u64; let plen=le_u64(&data[12..20]);
    if hlen > lim.max_header_bytes { return "RESOURCE_MAX_HEADER_BYTES"; }
    if plen > lim.max_payload_bytes { return "RESOURCE_MAX_PAYLOAD_BYTES"; }
    let expected=match 20u64.checked_add(hlen).and_then(|x|x.checked_add(plen)).and_then(|x|x.checked_add(32)){Some(x)=>x,None=>return "FORMAT_LENGTH"};
    if expected != data.len() as u64 { return "FORMAT_LENGTH"; }
    let mut h=Sha256::new(); h.update(&data[..data.len()-32]);
    if h.finalize().as_slice()!=&data[data.len()-32..] { return "INTEGRITY_BLOCK_SHA256"; }
    let hs=20usize; let he=hs+hlen as usize; let pe=he+plen as usize;
    let meta:Value=match serde_json::from_slice(&data[hs..he]){Ok(v)=>v,Err(_)=>return "FORMAT_JSON"};
    let obj=match meta.as_object(){Some(v)=>v,None=>return "FORMAT_JSON_ROOT"};
    let streams=match obj.get("streams").and_then(Value::as_array){Some(v)=>v,None=>return "FORMAT_STREAMS"};
    if streams.len() as u64 > lim.max_stream_count { return "RESOURCE_MAX_STREAM_COUNT"; }
    let wc=match obj.get("word_count").and_then(Value::as_u64){Some(v)=>v,None=>return "FORMAT_WORD_COUNT"};
    if wc > lim.max_tensor_words { return "RESOURCE_MAX_TENSOR_WORDS"; }
    if wc > lim.max_block_words { return "RESOURCE_MAX_BLOCK_WORDS"; }
    let payload=&data[he..pe]; let mut occupied:Vec<(u64,u64)>=Vec::new(); let mut names=HashSet::<String>::new(); let mut decoded_total=0u64;
    for d in streams {
        let o=match d.as_object(){Some(v)=>v,None=>return "FORMAT_DESCRIPTOR"};
        let name=match o.get("name").and_then(Value::as_str){Some(v) if !v.is_empty()=>v,_=>return "FORMAT_STREAM_NAME"};
        if !names.insert(name.to_owned()) { return "FORMAT_STREAM_NAME"; }
        let off=match is_nonnegative_u64(o.get("offset")){Some(v)=>v,None=>return "FORMAT_DESCRIPTOR"};
        let len=match is_nonnegative_u64(o.get("length")){Some(v)=>v,None=>return "FORMAT_DESCRIPTOR"};
        let end=match off.checked_add(len){Some(v)=>v,None=>return "FORMAT_STREAM_BOUNDS"};
        if end>plen { return "FORMAT_STREAM_BOUNDS"; }
        if occupied.iter().any(|(a,b)| std::cmp::max(off,*a)<std::cmp::min(end,*b)){return "FORMAT_STREAM_OVERLAP";}
        occupied.push((off,end));
        let digest=match o.get("sha256").and_then(Value::as_str){Some(v)=>v,None=>return "INTEGRITY_STREAM_SHA256"};
        let mut sh=Sha256::new(); sh.update(&payload[off as usize..end as usize]); let got=format!("{:x}",sh.finalize());
        if got!=digest { return "INTEGRITY_STREAM_SHA256"; }
        let dl=if let Some(v)=o.get("decoded_length") { match v.as_u64(){Some(x)=>x,None=>return "FORMAT_DECODED_LENGTH"} } else if o.get("encoding").and_then(Value::as_str).unwrap_or("raw")=="raw" { len } else { 0 };
        if dl > lim.max_stream_decompressed_bytes { return "RESOURCE_MAX_STREAM_DECOMPRESSED_BYTES"; }
        decoded_total=match decoded_total.checked_add(dl){Some(v)=>v,None=>return "RESOURCE_MAX_ARENA_BYTES"};
    }
    let arena=match wc.checked_mul(2).and_then(|x|x.checked_add(decoded_total)){Some(v)=>v,None=>return "RESOURCE_MAX_ARENA_BYTES"};
    if arena > lim.max_arena_bytes { return "RESOURCE_MAX_ARENA_BYTES"; }
    if obj.get("format").and_then(Value::as_str)!=Some("ExactProgressiveTensorBlock") { return "FORMAT_SEMANTIC_FORMAT"; }
    match obj.get("version").and_then(Value::as_u64){Some(1..=4)=>{},_=>return "FORMAT_SEMANTIC_VERSION"}
    "OK"
}

fn main(){
    let args:Vec<String>=env::args().collect(); if args.len()!=3{eprintln!("usage: eptb-parser <corpus.json> <report.json>");std::process::exit(64)}
    let corpus:Corpus=serde_json::from_slice(&fs::read(&args[1]).expect("read corpus")).expect("parse corpus");
    let mut rows=Vec::new(); let mut mismatches=0usize;
    for c in corpus.cases { let blob=decode_hex(&c.blob_hex).expect("hex"); let actual=classify(&blob,&c.limits).to_owned(); let pass=actual==c.expected; if !pass{mismatches+=1}; rows.push(Row{id:c.id,expected:c.expected,actual,pass}); }
    let report=Report{format:"EPTBRustParserParity",version:"0.4.0",case_count:rows.len(),mismatch_count:mismatches,cases:rows};
    fs::write(&args[2],serde_json::to_vec_pretty(&report).unwrap()).expect("write report");
    println!("cases={} mismatches={}",report.case_count,report.mismatch_count);
    if mismatches!=0{std::process::exit(2)}
}

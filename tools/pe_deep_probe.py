#!/usr/bin/env python3
"""Read-only PE/.NET container inspection. Does not execute or unpack protected code."""
import argparse, hashlib, json, pathlib, re, struct
import pefile

PATTERNS = {
 "routeros_mikrotik": re.compile(r"(?i)routeros|mikrotik|user.?manager|hotspot|radius|winbox|/ip(?:/|\s)|/tool(?:/|\s)|8728|8729"),
 "network_protocol": re.compile(r"(?i)TcpClient|TcpListener|NetworkStream|Socket|WebRequest|HttpWebRequest|HttpWebResponse|HttpClient|FtpWebRequest|ConnectAsync|GetResponse|SendAsync|Receive"),
 "database_storage": re.compile(r"(?i)OleDb|Odbc|Data\.mdb|\.accdb|SQLite|SELECT\s+.{0,80}\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DataSet|DataTable|SqlConnection|OleDbConnection"),
 "ui_and_operations": re.compile(r"(?i)button|btn[A-Z_]|Form\d|InitializeComponent|Click|Selling.?points|tableSales|tableSessions|columnuser|columnprice|expiration_date|first_login|total_download|total_time|freeze|unfreeze|recharge|disconnect|kick|voucher|ticket|card|profile|session"),
 "urls_and_paths": re.compile(r"(?i)https?://|ftp://|\\\\[A-Za-z0-9_.-]+\\|[A-Za-z]:\\\\|\.config|\.mdb|\.rpt")
}
def align4(n): return (n+3)&~3
def read_metadata_streams(pe):
    out={"present":False,"streams":[],"errors":[]}
    try:
        cli=pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        if not cli.VirtualAddress: return out
        cli_data=pe.get_data(cli.VirtualAddress,72)
        md_rva=struct.unpack_from("<I",cli_data,8)[0]
        md_size=struct.unpack_from("<I",cli_data,12)[0]
        blob=pe.get_data(md_rva,md_size)
        if len(blob)<20 or blob[:4] != b"BSJB":
            out["errors"].append("CLR metadata root missing BSJB signature"); return out
        out["present"]=True
        major,minor,reserved,verlen=struct.unpack_from("<HHII",blob,4)
        ver=blob[16:16+verlen].split(b"\0",1)[0].decode("ascii","replace")
        pos=align4(16+verlen)
        flags,count=struct.unpack_from("<HH",blob,pos); pos+=4
        out.update({"metadata_version":ver,"major":major,"minor":minor,"flags":flags,"stream_count_declared":count,"metadata_rva":md_rva,"metadata_size":md_size})
        seen={}
        for i in range(min(count,128)):
            if pos+8>len(blob): out["errors"].append("truncated stream header"); break
            off,size=struct.unpack_from("<II",blob,pos); pos+=8
            end=blob.find(b"\0",pos,min(pos+64,len(blob)))
            if end<0: out["errors"].append("unterminated stream name"); break
            name=blob[pos:end].decode("ascii","replace"); pos=align4(end+1)
            dup=name in seen; seen[name]=seen.get(name,0)+1
            out["streams"].append({"name":name,"offset":off,"size":size,"duplicate":dup,"within_metadata_bounds":off+size<=len(blob)})
    except Exception as e: out["errors"].append(type(e).__name__+": "+str(e))
    return out
def extract_strings(data, wide=False):
    rx=re.compile(rb"(?:[\x20-\x7e]\x00){4,}") if wide else re.compile(rb"[\x20-\x7e]{4,}")
    for m in rx.finditer(data):
        b=m.group(0); s=(b.decode("utf-16le","replace") if wide else b.decode("ascii","replace")).strip()
        if s: yield m.start(),s
def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--out",required=True); ap.add_argument("files",nargs="+"); a=ap.parse_args()
    out=pathlib.Path(a.out); out.mkdir(parents=True,exist_ok=True)
    for f in a.files:
        p=pathlib.Path(f); data=p.read_bytes(); safe=re.sub(r"[^A-Za-z0-9_.-]+","_",p.stem)[:100]
        pe=pefile.PE(data=data, fast_load=False)
        row={"file":str(p),"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest(),
             "machine":hex(pe.FILE_HEADER.Machine),"timestamp":pe.FILE_HEADER.TimeDateStamp,
             "characteristics":hex(pe.FILE_HEADER.Characteristics),"entrypoint_rva":hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
             "image_base":hex(pe.OPTIONAL_HEADER.ImageBase),"subsystem":pe.OPTIONAL_HEADER.Subsystem,
             "sections":[],"imports":[],"resources":[],"overlay":None,"clr":read_metadata_streams(pe)}
        for s in pe.sections:
            row["sections"].append({"name":s.Name.rstrip(b"\0").decode("ascii","replace"),"virtual_address":hex(s.VirtualAddress),
              "virtual_size":s.Misc_VirtualSize,"raw_size":s.SizeOfRawData,"raw_pointer":s.PointerToRawData,
              "characteristics":hex(s.Characteristics),"entropy":round(s.get_entropy(),4),
              "writable":bool(s.Characteristics&0x80000000),"executable":bool(s.Characteristics&0x20000000)})
        try:
            for entry in getattr(pe,"DIRECTORY_ENTRY_IMPORT",[]):
                row["imports"].append({"dll":entry.dll.decode("ascii","replace"),"symbols":[(x.name.decode("ascii","replace") if x.name else "ordinal:"+str(x.ordinal)) for x in entry.imports]})
        except Exception as e: row["import_error"]=str(e)
        try:
            def walk(entries,prefix=""):
                for e in entries:
                    n=(e.name.decode("utf-8","replace") if e.name else "ID:"+str(e.id))
                    ident=prefix+"/"+n
                    if e.struct.DataIsDirectory: walk(e.directory.entries,ident)
                    else: row["resources"].append({"name":ident,"rva":hex(e.data.struct.OffsetToData),"size":e.data.struct.Size,"codepage":e.data.struct.CodePage})
            for root in getattr(pe,"DIRECTORY_ENTRY_RESOURCE",[]).entries: walk([root])
        except Exception as e: row["resource_error"]=str(e)
        try:
            ov=pe.get_overlay_data_start_offset()
            if ov is not None and ov<len(data):
                overlay=data[ov:]
                row["overlay"]={"offset":ov,"size":len(overlay),"sha256":hashlib.sha256(overlay).hexdigest()}
        except Exception as e: row["overlay_error"]=str(e)
        (out/(safe+".pe.json")).write_text(json.dumps(row,indent=2,ensure_ascii=False),encoding="utf-8")
        matches=[]
        for wide in (False,True):
            for off,s in extract_strings(data,wide):
                for label,rx in PATTERNS.items():
                    if rx.search(s):
                        if re.search(r"(?i)(password|passwd|token|secret|api.?key)\s*[:=]",s): s=re.sub(r"(?i)((?:password|passwd|token|secret|api.?key)\s*[:=]\s*)\S+",r"\1[REDACTED]",s)
                        if re.search(r"\b\d{6,}:[A-Za-z0-9_-]{25,}\b",s): s="[REDACTED_TOKEN]"
                        matches.append({"kind":label,"encoding":"utf16le" if wide else "ascii","offset":off,"text":s[:400]})
        seen=set(); clean=[]
        for m in matches:
            k=(m["kind"],m["encoding"],m["offset"],m["text"])
            if k not in seen: seen.add(k); clean.append(m)
        (out/(safe+".strings.json")).write_text(json.dumps(clean,indent=2,ensure_ascii=False),encoding="utf-8")
        print(p.name+": "+str(len(row["sections"]))+" sections; "+str(len(row["imports"]))+" import DLLs; "+str(len(row["resources"]))+" resources; "+str(len(clean))+" classified string hits")
if __name__=="__main__": main()

#!/usr/bin/env python3
"""Best-effort static .NET metadata and IL probe. Never executes target files."""
from __future__ import annotations
import argparse, json, pathlib, re
import dnfile
from dnfile.enums import MetadataTables
from dncil.cil.body import CilMethodBody
from dncil.cil.error import MethodBodyFormatError
from dncil.cil.body.reader import CilMethodBodyReaderBase
from dncil.clr.token import Token, StringToken, InvalidToken

KEYWORDS = re.compile(r"(?i)(routeros|mikrotik|user.?manager|hotspot|radius|winbox|tcpclient|socket|networkstream|webrequest|http|ftp|credential|password|username|login|connect|send|receive|oledb|access|mdb|sql|sales|session|voucher|ticket|card|print|crystal|report|profile|queue|address|firewall|first.?login|expiration|download|upload|speed|limit)")
SECRET = re.compile(r"(?i)(password|passwd|token|secret|api.?key)(\s*[:=]\s*)(\S+)")
TABLES = {table.value: table.name for table in MetadataTables}

class Reader(CilMethodBodyReaderBase):
    def __init__(self, pe, row):
        self.pe, self.offset = pe, pe.get_offset_from_rva(row.Rva)
    def read(self, n):
        data = self.pe.get_data(self.pe.get_rva_from_offset(self.offset), n)
        self.offset += n
        return data
    def tell(self): return self.offset
    def seek(self, offset):
        self.offset = offset
        return self.offset

def safe(value):
    s = str(value)
    s = SECRET.sub(lambda m: m.group(1)+m.group(2)+"[REDACTED]", s)
    s = re.sub(r"\b\d{6,}:[A-Za-z0-9_-]{25,}\b", "[REDACTED_BOT_TOKEN]", s)
    s = re.sub(r"(https?://)[^/@:\s]+:[^/@\s]+@", r"\1[REDACTED]@", s)
    return s[:500]

def resolve(pe, operand):
    if isinstance(operand, StringToken):
        try:
            item = pe.net.user_strings.get(operand.rid)
            return item.value if item is not None and item.value is not None else str(operand)
        except Exception: return str(operand)
    if isinstance(operand, Token):
        name = TABLES.get(operand.table, "")
        table = getattr(pe.net.mdtables, name, None) if name else None
        try: return table.rows[operand.rid-1] if table is not None else InvalidToken(operand.value)
        except Exception: return InvalidToken(operand.value)
    return operand

def describe(pe, operand):
    value = resolve(pe, operand)
    if isinstance(value, str): return '"' + safe(value) + '"'
    if isinstance(value, dnfile.mdtable.MemberRefRow):
        parent = getattr(getattr(value, "Class", None), "row", None)
        if parent is not None and hasattr(parent, "TypeName"):
            ns = str(getattr(parent, "TypeNamespace", "") or "")
            return safe((ns+"." if ns else "")+str(parent.TypeName)+"::"+str(value.Name))
    if isinstance(value, dnfile.mdtable.TypeRefRow):
        ns = str(getattr(value, "TypeNamespace", "") or "")
        return safe((ns+"." if ns else "")+str(value.TypeName))
    if isinstance(value, (dnfile.mdtable.MethodDefRow, dnfile.mdtable.FieldRow)):
        return safe(value.Name)
    return safe(value)

def analyze(path, outdir):
    result = {"file":path.name,"status":"started","tables":{},"types":[],"member_refs":[],"methods":[],"errors":[]}
    try:
        pe = dnfile.dnPE(str(path))
        if not getattr(pe,"net",None) or not getattr(pe.net,"mdtables",None):
            raise RuntimeError("No readable CLR metadata tables")
        tables = pe.net.mdtables
        for name in ("TypeDef","TypeRef","MethodDef","MemberRef","Field","Property","ManifestResource","AssemblyRef"):
            table = getattr(tables,name,None)
            result["tables"][name] = len(table.rows) if table is not None else 0
        owner = {}
        typedef = getattr(tables,"TypeDef",None)
        if typedef is not None:
            for td in typedef.rows:
                ns = str(getattr(td,"TypeNamespace","") or "")
                full = (ns+"." if ns else "")+str(td.TypeName)
                result["types"].append(full)
                try:
                    for ref in td.MethodList:
                        if getattr(ref,"row",None) is not None: owner[id(ref.row)] = full
                except Exception: pass
        refs = getattr(tables,"MemberRef",None)
        if refs is not None:
            for row in refs.rows:
                parent = getattr(getattr(row,"Class",None),"row",None)
                ns = str(getattr(parent,"TypeNamespace","") or "") if parent else ""
                typ = str(getattr(parent,"TypeName","") or "") if parent else ""
                target = (ns+"." if ns else "")+typ+"::"+str(row.Name)
                if KEYWORDS.search(target): result["member_refs"].append(safe(target))
        methods = getattr(tables,"MethodDef",None)
        if methods is not None:
            for rid,row in enumerate(methods.rows,1):
                name = str(row.Name); typ = owner.get(id(row),"<unknown type>")
                entry = {"rid":rid,"type":typ,"name":name,"rva":int(row.Rva),"calls":[],"strings":[],"il":[]}
                try:
                    if not row.Rva or not row.ImplFlags.miIL or row.Flags.mdAbstract or row.Flags.mdPinvokeImpl: continue
                    body = CilMethodBody(Reader(pe,row))
                    for insn in body.instructions:
                        operand = insn.operand
                        resolved = resolve(pe,operand) if isinstance(operand,Token) else operand
                        rendered = describe(pe,operand) if operand is not None else ""
                        op = str(insn.opcode)
                        if op in ("call","callvirt","newobj","ldftn","ldvirtftn","jmp") and rendered:
                            entry["calls"].append(rendered)
                        if isinstance(resolved,str) and KEYWORDS.search(resolved):
                            entry["strings"].append(safe(resolved))
                        if rendered and KEYWORDS.search(rendered):
                            entry["il"].append(f"{insn.offset:04X} {op} {rendered}")
                    combined = " ".join([typ,name]+entry["calls"]+entry["strings"]+entry["il"])
                    if KEYWORDS.search(combined): result["methods"].append(entry)
                except Exception as exc:
                    result["errors"].append(f"Method RID {rid} {typ}::{name}: {type(exc).__name__}: {safe(exc)}")
        result["status"]="parsed"
        result["warnings"]=[safe(w) for w in pe.get_warnings()] if hasattr(pe,"get_warnings") else []
    except Exception as exc:
        result["status"]="failed"; result["errors"].append(f"{type(exc).__name__}: {safe(exc)}")
    outdir.mkdir(parents=True,exist_ok=True)
    stem=path.stem
    (outdir/(stem+".dotnet-probe.json")).write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding="utf-8")
    tick=chr(96)
    lines=[f"# .NET static probe: {path.name}","",f"- Status: **{result['status']}**","","## Metadata table counts",""]
    lines += [f"- {k}: {v}" for k,v in result["tables"].items()] or ["- No table counts."]
    lines += ["","## Type definitions",""]+[f"- {tick}{safe(x)}{tick}" for x in result["types"][:1000]]
    lines += ["","## Relevant external/member references",""]+[f"- {tick}{safe(x)}{tick}" for x in result["member_refs"][:1000]]
    lines += ["","## Relevant methods and IL evidence",""]
    for m in result["methods"][:1000]:
        lines += [f"### {tick}{safe(m['type'])}::{safe(m['name'])}{tick} (RID {m['rid']}, RVA 0x{m['rva']:X})",""]
        if m["calls"]: lines += ["Calls: "+"; ".join(f"{tick}{safe(x)}{tick}" for x in m["calls"][:80]),""]
        if m["strings"]: lines += ["String literals: "+"; ".join(f"{tick}{safe(x)}{tick}" for x in m["strings"][:80]),""]
        lines += [f"- IL: {tick}{safe(x)}{tick}" for x in m["il"][:160]]+[""]
    lines += ["## Parse errors / limitations",""]+[f"- {safe(x)}" for x in result["errors"][:300]]
    lines += ["","> Static metadata/IL parsing only. No target code is executed. Evidence still requires call-flow review."]
    (outdir/(stem+".dotnet-probe.md")).write_text("\n".join(lines)+"\n",encoding="utf-8")
    print(f"{path.name}: {result['status']}; types={len(result['types'])}; member_refs={len(result['member_refs'])}; relevant_methods={len(result['methods'])}; errors={len(result['errors'])}")

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--out",required=True)
    ap.add_argument("assemblies",nargs="+")
    args=ap.parse_args()
    for item in args.assemblies: analyze(pathlib.Path(item),pathlib.Path(args.out))

if __name__=="__main__": main()

using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

if (args.Length != 2) {
    Console.Error.WriteLine("Usage: dnlib_probe <input-assembly> <output-directory>");
    return 2;
}
string input = args[0], output = args[1];
Directory.CreateDirectory(output);
string stem = Path.GetFileNameWithoutExtension(input);
string report = Path.Combine(output, stem + ".dnlib.md");
string methodsPath = Path.Combine(output, stem + ".method-map.txt");
string literalsPath = Path.Combine(output, stem + ".safe-literals.txt");
string resourcesPath = Path.Combine(output, stem + ".resources.txt");
string tracePath = Path.Combine(output, stem + ".targeted-il.txt");
string eventsPath = Path.Combine(output, stem + ".ui-event-map.txt");
var log = new StringBuilder();
var interestingCall = new Regex(@"(?i)(System\.Net|System\.Data|System\.IO|System\.Windows\.Forms|OleDb|Odbc|SqlClient|TcpClient|NetworkStream|WebRequest|HttpWebRequest|FtpWebRequest|NetworkCredential|StreamReader|StreamWriter|BinaryReader|BinaryWriter|Encoding|IPAddress|Dns|Socket|RouterOS|MikroTik|Hotspot|User.?Manager|CrystalDecisions|Process|Registry|Configuration|Settings)");
var eventCall = new Regex(@"(?i)(add_Click|add_MouseClick|add_DoubleClick|add_LinkClicked|add_ColumnClick)");
var routerCommand = new Regex(@"^/(ip|user|tool|queue|system|interface|ppp|radius|routing|caps-man|certificate|file|log|snmp|disk|partitions|mpls|ipv6)(\s|/)", RegexOptions.IgnoreCase);
var safeLiteral = new Regex(@"(?i)(hotspot|user.?manager|mikrotik|routeros|radius|tcpclient|networkstream|webrequest|httpwebrequest|ftpwebrequest|oledb|selling.?points|tablesales|tablesessions|columnuser|columnprice|expiration_date|first_login|total_download|total_time|^btn[A-Za-z0-9_]+$|^form[A-Za-z0-9_]+$|^https?://[^/@\s]+$)");
try {
    using var module = ModuleDefMD.Load(input);
    var types = module.GetTypes().ToList();
    var methods = types.SelectMany(t => t.Methods).ToList();
    log.AppendLine("# dnlib static parse report\n");
    log.AppendLine("- Input: " + Path.GetFileName(input));
    log.AppendLine("- Module: " + module.Name);
    log.AppendLine("- Runtime: " + module.RuntimeVersion);
    log.AppendLine("- Types: " + types.Count);
    log.AppendLine("- Methods: " + methods.Count);
    log.AppendLine("- Assembly: " + (module.Assembly?.FullName ?? "(no assembly definition)") + "\n");
    var calls = new SortedSet<string>();
    var literals = new SortedSet<string>();
    var targetedIl = new StringBuilder();
    var uiEvents = new SortedSet<string>();
    foreach (var method in methods) {
        if (!method.HasBody) continue;
        var instructions = method.Body.Instructions;
        bool hasNetworkCall = instructions.Any(ins =>
            (ins.OpCode == OpCodes.Call || ins.OpCode == OpCodes.Callvirt || ins.OpCode == OpCodes.Newobj)
            && interestingCall.IsMatch(ins.Operand?.ToString() ?? ""));
        bool hasUiEventHook = instructions.Any(ins =>
            (ins.OpCode == OpCodes.Call || ins.OpCode == OpCodes.Callvirt)
            && eventCall.IsMatch(ins.Operand?.ToString() ?? ""));
        if (hasNetworkCall || hasUiEventHook) {
            targetedIl.AppendLine("\\n## " + method.FullName);
            if (hasNetworkCall) targetedIl.AppendLine("TRACE_KIND=NETWORK_OR_DATA");
            if (hasUiEventHook) targetedIl.AppendLine("TRACE_KIND=UI_EVENT_WIRING");
        }
        foreach (var ins in instructions) {
            string target = ins.Operand?.ToString() ?? "";
            if (ins.OpCode == OpCodes.Call || ins.OpCode == OpCodes.Callvirt || ins.OpCode == OpCodes.Newobj
                || ins.OpCode == OpCodes.Ldftn || ins.OpCode == OpCodes.Ldvirtftn) {
                if (interestingCall.IsMatch(target))
                    calls.Add(method.FullName + " -> " + target);
                if (hasNetworkCall || hasUiEventHook)
                    targetedIl.AppendLine($"{ins.Offset:X4}: {ins.OpCode.Name} {target}");
                if (hasUiEventHook && eventCall.IsMatch(target) && (ins.OpCode == OpCodes.Call || ins.OpCode == OpCodes.Callvirt)) {
                    foreach (var handlerIns in instructions.Where(x => x.OpCode == OpCodes.Ldftn || x.OpCode == OpCodes.Ldvirtftn)) {
                        string handler = handlerIns.Operand?.ToString() ?? "";
                        if (!String.IsNullOrEmpty(handler))
                            uiEvents.Add(method.FullName + " => " + target + " => " + handler);
                    }
                }
            } else if (ins.OpCode == OpCodes.Ldstr && ins.Operand is string value) {
                if (value.Length <= 500 && !Regex.IsMatch(value, @"(?i)(password|passwd|token|secret|api.?key)\\s*[:=]")) {
                    if (routerCommand.IsMatch(value.Trim())) {
                        string safeValue = Regex.Replace(value.Replace("\\r"," ").Replace("\\n"," "), @"(?i)\\b(password|passwd|secret|token|community|passphrase)\\s*=\\s*(""[^""]*""|\\S+)", "$1=[REDACTED]");
                        literals.Add(method.FullName + " :: " + safeValue);
                        if (hasNetworkCall || hasUiEventHook) targetedIl.AppendLine($"{ins.Offset:X4}: ldstr {safeValue}");
                    } else if (hasNetworkCall || hasUiEventHook) {
                        targetedIl.AppendLine($"{ins.Offset:X4}: ldstr [non-command string omitted]");
                    }
                }
            } else if (hasNetworkCall || hasUiEventHook) {
                if (ins.OpCode.Name.StartsWith("ldc.i4", StringComparison.Ordinal) || ins.OpCode.Name.StartsWith("ldc.i8", StringComparison.Ordinal))
                    targetedIl.AppendLine($"{ins.Offset:X4}: {ins.OpCode.Name} {target}");
                else if (ins.OpCode == OpCodes.Ldarg || ins.OpCode == OpCodes.Ldarg_S || ins.OpCode == OpCodes.Ldloc || ins.OpCode == OpCodes.Ldloc_S
                    || ins.OpCode == OpCodes.Stloc || ins.OpCode == OpCodes.Stloc_S || ins.OpCode.FlowControl == FlowControl.Branch
                    || ins.OpCode.FlowControl == FlowControl.Cond_Branch)
                    targetedIl.AppendLine($"{ins.Offset:X4}: {ins.OpCode.Name} {target}");
            }
        }
    }
    File.WriteAllText(tracePath, targetedIl.ToString(), new UTF8Encoding(false));
    File.WriteAllLines(eventsPath, uiEvents, new UTF8Encoding(false));
    File.WriteAllLines(methodsPath, calls, new UTF8Encoding(false));
    File.WriteAllLines(literalsPath, literals, new UTF8Encoding(false));
    using (var rs = new StreamWriter(resourcesPath, false, new UTF8Encoding(false))) {
        foreach (var r in module.Resources) {
            rs.WriteLine(r.ResourceType + " " + r.Name);
            // Resource names/types are sufficient for this inventory. Avoid relying on
            // version-specific DataReader conversion helpers for resource byte extraction.
        }
    }
    log.AppendLine("- Parse status: **parsed**");
    log.AppendLine("- Interesting method-call edges: " + calls.Count);
    log.AppendLine("- Safe command/identifier literals: " + literals.Count);
    log.AppendLine("- Resource inventory: " + Path.GetFileName(resourcesPath));
    log.AppendLine("- Targeted network/data and UI event IL: " + Path.GetFileName(tracePath));
    log.AppendLine("- UI event hookup map: " + Path.GetFileName(eventsPath));
    log.AppendLine("- Method map: " + Path.GetFileName(methodsPath));
    log.AppendLine("- Only selected non-secret identifiers and call targets are emitted; complete IL and arbitrary literals are not published.");
} catch (Exception ex) {
    log.AppendLine("# dnlib static parse report\n");
    log.AppendLine("- Input: " + Path.GetFileName(input));
    log.AppendLine("- Parse status: **failed**");
    log.AppendLine("- Exception: " + ex.GetType().FullName);
    log.AppendLine("- Message: " + ex.Message);
    log.AppendLine("- No unpacking, patching, or protection bypass was attempted.");
    File.WriteAllText(methodsPath, "No method map: metadata parsing failed.\n", new UTF8Encoding(false));
    File.WriteAllText(literalsPath, "No safe literals: metadata parsing failed.\n", new UTF8Encoding(false));
    File.WriteAllText(resourcesPath, "No resources enumerated: metadata parsing failed.\n", new UTF8Encoding(false));
}
File.WriteAllText(report, log.ToString(), new UTF8Encoding(false));
Console.WriteLine(log.ToString());
return 0;

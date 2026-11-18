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
string callerPath = Path.Combine(output, stem + ".network-callers.txt");
string callerIlPath = Path.Combine(output, stem + ".network-caller-il.txt");
string typePath = Path.Combine(output, stem + ".type-inventory.txt");
string formEventPath = Path.Combine(output, stem + ".form-event-candidates.txt");
string formDelegatePath = Path.Combine(output, stem + ".form-delegate-map.txt");
string literalInventoryPath = Path.Combine(output, stem + ".literal-inventory.txt");
string formHandlerIlPath = Path.Combine(output, stem + ".form-handler-il.txt");
string deepFormIlPath = Path.Combine(output, stem + ".deep-form-il.txt");
var log = new StringBuilder();
var interestingCall = new Regex(@"(?i)(System\.Net|System\.Data\.OleDb|System\.Data\.Common\.DbCommand|System\.Data\.Common\.DbData|System\.Windows\.Forms|OleDb|Odbc|SqlClient|TcpClient|NetworkStream|WebRequest|HttpWebRequest|FtpWebRequest|NetworkCredential|IPAddress|Dns|Socket|RouterOS|MikroTik|Hotspot|User.?Manager|CrystalDecisions)");
var eventCall = new Regex(@"(?i)(add_[A-Za-z0-9_]+|EventHandlerList::AddHandler)");
var directNetworkCall = new Regex(@"(?i)(System\.Net|TcpClient|NetworkStream|WebRequest|HttpWebRequest|FtpWebRequest|NetworkCredential|Socket|IPAddress|Dns)");
var directDataCall = new Regex(@"(?i)(OleDb|Odbc|SqlClient|DbCommand|DbDataAdapter|DbDataReader)");
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
            targetedIl.AppendLine("\n## " + method.FullName);
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
                if (value.Length <= 500 && !Regex.IsMatch(value, @"(?i)(password|passwd|token|secret|api.?key)\s*[:=]")) {
                    if (routerCommand.IsMatch(value.Trim())) {
                        string safeValue = Regex.Replace(value.Replace("\r"," ").Replace("\n"," "), @"(?i)\b(password|passwd|secret|token|community|passphrase)\s*=\s*(""[^""]*""|\S+)", "$1=[REDACTED]");
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
    // Build reverse call chains using resolved MethodDef metadata tokens, not obfuscated display names.
    var directTargets = new HashSet<MethodDef>();
    foreach (var method in methods) {
        if (!method.HasBody) continue;
        bool direct = method.Body.Instructions.Any(ins =>
            (ins.OpCode == OpCodes.Call || ins.OpCode == OpCodes.Callvirt || ins.OpCode == OpCodes.Newobj)
            && (directNetworkCall.IsMatch(ins.Operand?.ToString() ?? "") || directDataCall.IsMatch(ins.Operand?.ToString() ?? "")));
        if (direct) directTargets.Add(method);
    }
    var callerLines = new SortedSet<string>();
    var callerIl = new StringBuilder();
    var seenTokens = new HashSet<uint>(directTargets.Select(m => m.MDToken.Raw));
    var frontierTokens = new HashSet<uint>(seenTokens);
    foreach (var target in directTargets)
        callerLines.Add("DIRECT_API_METHOD TOKEN=" + target.MDToken.Raw.ToString("X8") + " " + target.FullName);
    for (int depth = 1; depth <= 6 && frontierTokens.Count > 0; depth++) {
        var nextMethods = new HashSet<MethodDef>();
        foreach (var method in methods) {
            if (!method.HasBody || seenTokens.Contains(method.MDToken.Raw)) continue;
            var matches = new SortedSet<string>();
            foreach (var ins in method.Body.Instructions) {
                if (ins.OpCode != OpCodes.Call && ins.OpCode != OpCodes.Callvirt && ins.OpCode != OpCodes.Newobj
                    && ins.OpCode != OpCodes.Ldftn && ins.OpCode != OpCodes.Ldvirtftn) continue;
                if (ins.Operand is not IMethod methodRef) continue;
                MethodDef? resolved = null;
                try { resolved = methodRef.ResolveMethodDef(); } catch { }
                if (resolved != null && frontierTokens.Contains(resolved.MDToken.Raw)) {
                    matches.Add("TOKEN=" + resolved.MDToken.Raw.ToString("X8") + " " + resolved.FullName);
                    nextMethods.Add(method);
                }
            }
            if (matches.Count == 0) continue;
            callerLines.Add("DEPTH=" + depth + " TOKEN=" + method.MDToken.Raw.ToString("X8") + " " + method.FullName + " => " + String.Join(" || ", matches));
            callerIl.AppendLine("\n## DEPTH=" + depth + " TOKEN=" + method.MDToken.Raw.ToString("X8") + " " + method.FullName);
            foreach (var ins in method.Body.Instructions) {
                string operand = ins.Operand?.ToString() ?? "";
                if (ins.OpCode == OpCodes.Call || ins.OpCode == OpCodes.Callvirt || ins.OpCode == OpCodes.Newobj
                    || ins.OpCode == OpCodes.Ldftn || ins.OpCode == OpCodes.Ldvirtftn) {
                    callerIl.AppendLine($"{ins.Offset:X4}: {ins.OpCode.Name} {operand}");
                } else if (ins.OpCode == OpCodes.Ldstr && ins.Operand is string str) {
                    bool sensitive = Regex.IsMatch(str, @"(?i)(password|passwd|token|secret|api.?key|community|passphrase)\s*[:=]");
                    if (routerCommand.IsMatch(str.Trim()) && str.Length <= 500 && !sensitive)
                        callerIl.AppendLine($"{ins.Offset:X4}: ldstr {str}");
                    else if (sensitive)
                        callerIl.AppendLine($"{ins.Offset:X4}: ldstr [REDACTED]");
                    else
                        callerIl.AppendLine($"{ins.Offset:X4}: ldstr [non-command string omitted]");
                } else if (ins.OpCode.Name.StartsWith("ldc.i4", StringComparison.Ordinal)
                    || ins.OpCode.Name.StartsWith("ldc.i8", StringComparison.Ordinal)
                    || ins.OpCode.FlowControl == FlowControl.Branch
                    || ins.OpCode.FlowControl == FlowControl.Cond_Branch) {
                    callerIl.AppendLine($"{ins.Offset:X4}: {ins.OpCode.Name} {operand}");
                }
            }
        }
        foreach (var method in nextMethods) seenTokens.Add(method.MDToken.Raw);
        frontierTokens = new HashSet<uint>(nextMethods.Select(m => m.MDToken.Raw));
    }
    var literalInventory = new SortedSet<string>();
    foreach (var method in methods) if (method.HasBody) foreach (var ins in method.Body.Instructions)
        if (ins.OpCode == OpCodes.Ldstr && ins.Operand is string value) {
            bool sensitive = Regex.IsMatch(value, @"(?i)(password|passwd|token|secret|api.?key|community|passphrase)\s*[:=]")
                || Regex.IsMatch(value, @"(?i)^(?:[A-Z0-9+/]{24,}={0,2}|[a-f0-9]{32,})$");
            string category = routerCommand.IsMatch(value.Trim()) ? "ROUTEROS_COMMAND_CANDIDATE"
                : Regex.IsMatch(value, @"(?i)(tcp|host|port|address|server|api|router|mikrotik)") ? "NETWORK_RELATED"
                : Regex.IsMatch(value, @"(?i)(select |insert |update |delete | from | where )") ? "SQL_RELATED"
                : Regex.IsMatch(value, @"(?i)(button|click|form|user|sales|session|hotspot|profile|print|report)") ? "UI_OR_DOMAIN"
                : "OTHER";
            string shown = sensitive ? "[REDACTED]" : (value.Length > 240 ? value.Substring(0,240) + "[TRUNCATED]" : value.Replace("\r"," ").Replace("\n"," "));
            literalInventory.Add(method.FullName + " IL_" + ins.Offset.ToString("X4") + " [" + category + "] len=" + value.Length + " sha256=" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))) + " value=" + shown);
        }
    var formEventCandidates = new SortedSet<string>();
    var formDelegates = new SortedSet<string>();
    foreach (var type in types.Where(t => t.BaseType?.FullName?.Contains("System.Windows.Forms.Form", StringComparison.OrdinalIgnoreCase) == true)) {
        foreach (var method in type.Methods) {
            string signature = method.FullName;
            if (Regex.IsMatch(signature, @"(?i)System\.Object,.*(EventArgs|MouseEventArgs|KeyEventArgs|DataGridView.*EventArgs|LinkLabelLinkClickedEventArgs|FormClosingEventArgs|FormClosedEventArgs)")) {
                formEventCandidates.Add("TYPE=" + type.FullName + " TOKEN=" + method.MDToken.Raw.ToString("X8") + " " + signature);
            }
            if (!method.HasBody) continue;
            for (int eventIndex = 0; eventIndex < method.Body.Instructions.Count; eventIndex++) {
                var ins = method.Body.Instructions[eventIndex];
                if (ins.OpCode == OpCodes.Ldftn || ins.OpCode == OpCodes.Ldvirtftn) {
                    string target = ins.Operand is IMethod methodRef1 ? methodRef1.FullName : (ins.Operand?.ToString() ?? "");
                    formDelegates.Add("FORM_METHOD=" + method.FullName + " => " + target);
                }
                if (ins.OpCode == OpCodes.Call || ins.OpCode == OpCodes.Callvirt) {
                    string target = ins.Operand is IMethod im ? im.FullName : (ins.Operand?.ToString() ?? "");
                    if (eventCall.IsMatch(target)) {
                        string handler = "(no nearby ldftn found)";
                        for (int k = eventIndex - 1; k >= Math.Max(0, eventIndex - 12); k--) {
                            var prior = method.Body.Instructions[k];
                            if (prior.OpCode == OpCodes.Ldftn || prior.OpCode == OpCodes.Ldvirtftn) {
                                handler = prior.Operand is IMethod handlerRef ? handlerRef.FullName : (prior.Operand?.ToString() ?? handler);
                                break;
                            }
                        }
                        formDelegates.Add("EVENT_ATTACH=" + method.FullName + " => " + target + " => HANDLER=" + handler);
                    }
                }
            }
        }
    }
    File.WriteAllLines(formEventPath, formEventCandidates, new UTF8Encoding(false));
    File.WriteAllLines(literalInventoryPath, literalInventory, new UTF8Encoding(false));
    File.WriteAllLines(formDelegatePath, formDelegates, new UTF8Encoding(false));
    var formHandlerIl = new StringBuilder();
    foreach (var type in types) {
        foreach (var method in type.Methods) {
            if (!method.HasBody) continue;
            string sig = method.FullName;
            bool eventCandidate = Regex.IsMatch(sig, @"(?i)System\.Object,.*(EventArgs|MouseEventArgs|KeyEventArgs|DataGridView.*EventArgs|LinkLabelLinkClickedEventArgs|FormClosingEventArgs|FormClosedEventArgs)");
            if (!eventCandidate) continue;
            formHandlerIl.AppendLine("\n## TOKEN=" + method.MDToken.Raw.ToString("X8") + " " + sig);
            foreach (var ins in method.Body.Instructions) {
                string operand = ins.Operand?.ToString() ?? "";
                if (ins.OpCode == OpCodes.Call || ins.OpCode == OpCodes.Callvirt || ins.OpCode == OpCodes.Newobj
                    || ins.OpCode == OpCodes.Ldftn || ins.OpCode == OpCodes.Ldvirtftn
                    || ins.OpCode == OpCodes.Ldstr
                    || ins.OpCode.Name.StartsWith("ldc.i4", StringComparison.Ordinal)
                    || ins.OpCode.Name.StartsWith("ldc.i8", StringComparison.Ordinal)
                    || ins.OpCode.FlowControl == FlowControl.Branch
                    || ins.OpCode.FlowControl == FlowControl.Cond_Branch) {
                    if (ins.OpCode == OpCodes.Ldstr && ins.Operand is string literal) {
                        bool sensitive = Regex.IsMatch(literal, @"(?i)(password|passwd|token|secret|api.?key|community|passphrase)\s*[:=]");
                        string shown = sensitive ? "[REDACTED]" : (literal.Length > 200 ? literal.Substring(0,200) + "[TRUNCATED]" : literal);
                        formHandlerIl.AppendLine($"{ins.Offset:X4}: ldstr {shown}");
                    } else {
                        formHandlerIl.AppendLine($"{ins.Offset:X4}: {ins.OpCode.Name} {operand}");
                    }
                }
            }
        }
    }
    File.WriteAllText(formHandlerIlPath, formHandlerIl.ToString(), new UTF8Encoding(false));
    var deepFormIl = new StringBuilder();
    foreach (var type in types) {
        bool isForm = type.BaseType?.FullName?.Contains("System.Windows.Forms.Form", StringComparison.OrdinalIgnoreCase) == true;
        bool hasDirectNetworkOrData = type.Methods.Any(m => m.HasBody && m.Body.Instructions.Any(ins =>
            (ins.OpCode == OpCodes.Call || ins.OpCode == OpCodes.Callvirt || ins.OpCode == OpCodes.Newobj)
            && (directNetworkCall.IsMatch(ins.Operand?.ToString() ?? "") || directDataCall.IsMatch(ins.Operand?.ToString() ?? ""))));
        if (!isForm || !hasDirectNetworkOrData) continue;
        deepFormIl.AppendLine("\n## TYPE TOKEN=" + type.MDToken.Raw.ToString("X8") + " " + type.FullName + " BASE=" + (type.BaseType?.FullName ?? ""));
        foreach (var field in type.Fields)
            deepFormIl.AppendLine("FIELD TOKEN=" + field.MDToken.Raw.ToString("X8") + " " + field.FieldType.FullName + " " + field.Name);
        foreach (var method in type.Methods) {
            deepFormIl.AppendLine("\n### METHOD TOKEN=" + method.MDToken.Raw.ToString("X8") + " " + method.FullName);
            if (!method.HasBody) { deepFormIl.AppendLine("[NO BODY]"); continue; }
            foreach (var ins in method.Body.Instructions) {
                string operand = ins.Operand?.ToString() ?? "";
                if (ins.OpCode == OpCodes.Ldstr && ins.Operand is string literal) {
                    bool sensitive = Regex.IsMatch(literal, @"(?i)(password|passwd|token|secret|api.?key|community|passphrase)\s*[:=]");
                    string shown = sensitive ? "[REDACTED]" :
                        (routerCommand.IsMatch(literal.Trim()) && literal.Length <= 500 ? literal.Replace("\\r"," ").Replace("\\n"," ") :
                        "[STRING len=" + literal.Length + " sha256=" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(literal))) + "]");
                    deepFormIl.AppendLine($"{ins.Offset:X4}: ldstr {shown}");
                } else {
                    deepFormIl.AppendLine($"{ins.Offset:X4}: {ins.OpCode.Name} {operand}");
                }
            }
        }
    }
    File.WriteAllText(deepFormIlPath, deepFormIl.ToString(), new UTF8Encoding(false));
    using (var tw = new StreamWriter(typePath, false, new UTF8Encoding(false))) {
        tw.WriteLine("EntryPoint: " + (module.EntryPoint?.FullName ?? "(none)"));
        foreach (var type in types.OrderBy(t => t.FullName, StringComparer.Ordinal)) {
            bool hasDirectNetworkOrData = type.Methods.Any(m => m.HasBody && m.Body.Instructions.Any(ins =>
                (ins.OpCode == OpCodes.Call || ins.OpCode == OpCodes.Callvirt || ins.OpCode == OpCodes.Newobj)
                && (directNetworkCall.IsMatch(ins.Operand?.ToString() ?? "") || directDataCall.IsMatch(ins.Operand?.ToString() ?? ""))));
            tw.WriteLine("TYPE " + type.FullName + " BASE=" + (type.BaseType?.FullName ?? "(none)") + " METHODS=" + type.Methods.Count
                + " DIRECT_NETWORK_OR_DATA=" + hasDirectNetworkOrData);
            foreach (var method in type.Methods) {
                bool hasBody = method.HasBody;
                bool namedInteresting = Regex.IsMatch(method.Name.String, @"(?i)(InitializeComponent|Main|Click|Mouse|Double|Load|Shown|Closing|Activated|Form)");
                if (namedInteresting || method.Name == "InitializeComponent" || type.BaseType?.FullName?.Contains("System.Windows.Forms", StringComparison.OrdinalIgnoreCase) == true || hasDirectNetworkOrData)
                    tw.WriteLine("  METHOD " + method.FullName + " TOKEN=" + method.MDToken.Raw.ToString("X8") + " BODY=" + hasBody);
            }
        }
    }
    File.WriteAllLines(callerPath, callerLines, new UTF8Encoding(false));
    File.WriteAllText(callerIlPath, callerIl.ToString(), new UTF8Encoding(false));
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
    log.AppendLine("- Reverse network/database caller map: " + Path.GetFileName(callerPath));
    log.AppendLine("- Caller IL: " + Path.GetFileName(callerIlPath));
    log.AppendLine("- Type and form inventory: " + Path.GetFileName(typePath));
    log.AppendLine("- Form event candidate methods: " + Path.GetFileName(formEventPath));
    log.AppendLine("- Form delegate references: " + Path.GetFileName(formDelegatePath));
    log.AppendLine("- Classified string literal inventory (with hashes/redaction): " + Path.GetFileName(literalInventoryPath));
    log.AppendLine("- Event-handler candidate IL: " + Path.GetFileName(formHandlerIlPath));
    log.AppendLine("- Full sanitized IL for network/data-bearing Forms: " + Path.GetFileName(deepFormIlPath));
    log.AppendLine("- Method map: " + Path.GetFileName(methodsPath));
    log.AppendLine("- Full IL is emitted only for Forms that directly contain network/database API calls; non-command strings are hashed and sensitive-looking literals are redacted.");
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

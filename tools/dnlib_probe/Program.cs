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
var log = new StringBuilder();
var interestingCall = new Regex(@"(?i)(System\.Net|System\.Data|System\.IO|System\.Windows\.Forms|OleDb|Odbc|SqlClient|TcpClient|NetworkStream|WebRequest|HttpWebRequest|FtpWebRequest|RouterOS|MikroTik|Hotspot|User.?Manager|CrystalDecisions|Process|Registry|Configuration|Settings)");
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
    foreach (var method in methods) {
        if (!method.HasBody) continue;
        foreach (var ins in method.Body.Instructions) {
            if (ins.OpCode == OpCodes.Call || ins.OpCode == OpCodes.Callvirt || ins.OpCode == OpCodes.Newobj) {
                string target = ins.Operand?.ToString() ?? "";
                if (interestingCall.IsMatch(target))
                    calls.Add(method.FullName + " -> " + target);
            }
            if (ins.OpCode == OpCodes.Ldstr && ins.Operand is string value) {
                if (value.Length > 500 || Regex.IsMatch(value, @"(?i)(password|passwd|token|secret|api.?key)\s*[:=]")) continue;
                if (routerCommand.IsMatch(value.Trim()) || safeLiteral.IsMatch(value.Trim())) {
                    string safeValue = Regex.Replace(value.Replace("\r"," ").Replace("\n"," "), @"(?i)\b(password|passwd|secret|token|community|passphrase)\s*=\s*("[^"]*"|'[^']*'|\S+)", "$1=[REDACTED]");
                    literals.Add(method.FullName + " :: " + safeValue);
                }
            }
        }
    }
    File.WriteAllLines(methodsPath, calls, new UTF8Encoding(false));
    File.WriteAllLines(literalsPath, literals, new UTF8Encoding(false));
    using (var rs = new StreamWriter(resourcesPath, false, new UTF8Encoding(false))) {
        foreach (var r in module.Resources) {
            rs.WriteLine(r.ResourceType + " " + r.Name);
            if (r is EmbeddedResource er) {
                try {
                    using var stream = er.CreateReader().ToMemoryStream();
                    byte[] bytes = stream.ToArray();
                    rs.WriteLine("  bytes=" + bytes.Length + " sha256=" + Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant());
                } catch (Exception ex) { rs.WriteLine("  read-error=" + ex.GetType().Name + ": " + ex.Message); }
            }
        }
    }
    log.AppendLine("- Parse status: **parsed**");
    log.AppendLine("- Interesting method-call edges: " + calls.Count);
    log.AppendLine("- Safe command/identifier literals: " + literals.Count);
    log.AppendLine("- Resource inventory: " + Path.GetFileName(resourcesPath));
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

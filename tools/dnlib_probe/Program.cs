using System.Security.Cryptography;
using System.Text;
using dnlib.DotNet;

if (args.Length != 2) {
    Console.Error.WriteLine("Usage: dnlib_probe <input-assembly> <output-directory>");
    return 2;
}
string input = args[0], output = args[1];
Directory.CreateDirectory(output);
string stem = Path.GetFileNameWithoutExtension(input);
string report = Path.Combine(output, stem + ".dnlib.md");
string ilPath = Path.Combine(output, stem + ".il.txt");
string resourcesPath = Path.Combine(output, stem + ".resources.txt");
var log = new StringBuilder();
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
    using (var il = new StreamWriter(ilPath, false, new UTF8Encoding(false))) {
        foreach (var type in types) {
            il.WriteLine("\n// TYPE " + type.FullName);
            foreach (var method in type.Methods) {
                il.WriteLine("\n// METHOD " + method.MDToken + " " + method.FullName);
                if (!method.HasBody) { il.WriteLine("// no method body"); continue; }
                foreach (var ins in method.Body.Instructions)
                    il.WriteLine(ins.Offset.ToString("X4") + ": " + ins.OpCode + " " + (ins.Operand?.ToString() ?? ""));
                foreach (var eh in method.Body.ExceptionHandlers)
                    il.WriteLine("// EH " + eh.HandlerType + " try=" + eh.TryStart?.Offset + "-" + eh.TryEnd?.Offset + " handler=" + eh.HandlerStart?.Offset + "-" + eh.HandlerEnd?.Offset);
            }
        }
    }
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
    log.AppendLine("- IL dump: " + Path.GetFileName(ilPath));
    log.AppendLine("- Resource inventory: " + Path.GetFileName(resourcesPath));
} catch (Exception ex) {
    log.AppendLine("# dnlib static parse report\n");
    log.AppendLine("- Input: " + Path.GetFileName(input));
    log.AppendLine("- Parse status: **failed**");
    log.AppendLine("- Exception: " + ex.GetType().FullName);
    log.AppendLine("- Message: " + ex.Message);
    log.AppendLine("- No unpacking, patching, or protection bypass was attempted.");
    File.WriteAllText(ilPath, "No IL was emitted because metadata parsing failed.\n", new UTF8Encoding(false));
    File.WriteAllText(resourcesPath, "No resources were enumerated because metadata parsing failed.\n", new UTF8Encoding(false));
}
File.WriteAllText(report, log.ToString(), new UTF8Encoding(false));
Console.WriteLine(log.ToString());
return 0;

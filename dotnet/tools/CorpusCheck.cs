using System;
using System.Collections.Generic;
using System.Linq;
using Aegis.Security;

namespace Aegis.Security.Tools;

/// <summary>
/// Prints this SDK's verdict for each corpus case, so the shared parity test
/// can compare .NET against the other SDKs.
/// </summary>
public static class Program
{
    public static void Main()
    {
        var raw = Console.In.ReadToEnd();
        var cases = ParseStringArray(raw);

        var output = new System.Text.StringBuilder("{");
        for (var i = 0; i < cases.Count; i++)
        {
            var ids = Aegis.Rules
                .Where(r => r.Pattern.IsMatch(cases[i]))
                .Select(r => r.Id)
                .OrderBy(id => id, StringComparer.Ordinal)
                .ToList();

            if (i > 0)
            {
                output.Append(',');
            }

            output.Append(Aegis.Quote(cases[i])).Append(":[");
            output.Append(string.Join(",", ids.Select(Aegis.Quote)));
            output.Append(']');
        }

        Console.WriteLine(output.Append('}').ToString());
    }

    /// <summary>A minimal JSON string-array reader, so this tool needs no dependency.</summary>
    private static List<string> ParseStringArray(string json)
    {
        var values = new List<string>();
        var start = json.IndexOf('[');
        if (start < 0)
        {
            return values;
        }

        System.Text.StringBuilder? current = null;
        for (var i = start + 1; i < json.Length; i++)
        {
            var c = json[i];
            if (current is null)
            {
                if (c == '"')
                {
                    current = new System.Text.StringBuilder();
                }
                else if (c == ']')
                {
                    break;
                }

                continue;
            }

            if (c == '\\')
            {
                var next = json[++i];
                switch (next)
                {
                    case 'n': current.Append('\n'); break;
                    case 'r': current.Append('\r'); break;
                    case 't': current.Append('\t'); break;
                    case 'u':
                        current.Append((char)Convert.ToInt32(json.Substring(i + 1, 4), 16));
                        i += 4;
                        break;
                    default: current.Append(next); break;
                }
            }
            else if (c == '"')
            {
                values.Add(current.ToString());
                current = null;
            }
            else
            {
                current.Append(c);
            }
        }

        return values;
    }
}

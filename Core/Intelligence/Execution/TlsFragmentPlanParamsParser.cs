using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

namespace IspAudit.Core.Intelligence.Execution;

/// <summary>
/// Парсер параметров стратегии TlsFragment из INTEL BypassPlan.
/// Важно: класс не зависит от WPF/VM и остаётся детерминированным.
/// </summary>
public static class TlsFragmentPlanParamsParser
{
    public sealed record ParsedTlsFragmentParams(
        string? PresetName,
        IReadOnlyList<int>? Sizes,
        bool? AutoAdjustAggressive);

    public static bool TryParse(Dictionary<string, object?> parameters, out ParsedTlsFragmentParams parsed)
    {
        parsed = new ParsedTlsFragmentParams(PresetName: null, Sizes: null, AutoAdjustAggressive: null);

        if (parameters == null || parameters.Count == 0)
        {
            return false;
        }

        string? presetName = null;
        if (TryExtractTlsFragmentPresetName(parameters, out var pn))
        {
            presetName = pn;
        }

        List<int>? sizes = null;
        if (TryExtractTlsFragmentSizes(parameters, out var s))
        {
            sizes = s;
        }

        bool? autoAdjustAggressive = null;
        if (TryExtractAutoAdjustAggressive(parameters, out var aa))
        {
            autoAdjustAggressive = aa;
        }

        if (presetName == null && sizes == null && autoAdjustAggressive == null)
        {
            return false;
        }

        parsed = new ParsedTlsFragmentParams(presetName, sizes, autoAdjustAggressive);
        return true;
    }

    private static bool TryExtractTlsFragmentPresetName(Dictionary<string, object?> parameters, out string presetName)
    {
        presetName = string.Empty;

        if (TryGetStringParam(parameters, "TlsFragmentPreset", out presetName)) return true;
        if (TryGetStringParam(parameters, "TlsFragmentPresetName", out presetName)) return true;
        if (TryGetStringParam(parameters, "Preset", out presetName)) return true;
        if (TryGetStringParam(parameters, "PresetName", out presetName)) return true;
        if (TryGetStringParam(parameters, "FragmentPreset", out presetName)) return true;

        return false;
    }

    private static bool TryExtractAutoAdjustAggressive(Dictionary<string, object?> parameters, out bool enabled)
    {
        enabled = false;

        if (!parameters.TryGetValue("AutoAdjustAggressive", out var raw) || raw == null)
        {
            return false;
        }

        switch (raw)
        {
            case bool b:
                enabled = b;
                return true;
            case JsonElement je when je.ValueKind == JsonValueKind.True || je.ValueKind == JsonValueKind.False:
                enabled = je.GetBoolean();
                return true;
            case string s when bool.TryParse(s, out var parsed):
                enabled = parsed;
                return true;
        }

        return false;
    }

    private static bool TryExtractTlsFragmentSizes(Dictionary<string, object?> parameters, out List<int> sizes)
    {
        sizes = new List<int>();

        if (!parameters.TryGetValue("TlsFragmentSizes", out var raw) || raw == null)
        {
            return false;
        }

        List<int>? parsed = raw switch
        {
            int[] arr => arr.ToList(),
            List<int> list => list.ToList(),
            IReadOnlyList<int> ro => ro.ToList(),
            IEnumerable<int> en => en.ToList(),
            JsonElement je => TryParseIntArrayFromJsonElement(je),
            string s => TryParseIntArrayFromString(s),
            IEnumerable<object> obj => TryParseIntArrayFromObjects(obj),
            _ => null
        };

        if (parsed == null)
        {
            return false;
        }

        sizes = NormalizeFragmentSizes(parsed);
        return sizes.Count > 0;
    }

    private static bool TryGetStringParam(Dictionary<string, object?> parameters, string key, out string value)
    {
        value = string.Empty;
        if (!parameters.TryGetValue(key, out var raw) || raw == null)
        {
            return false;
        }

        switch (raw)
        {
            case string s:
                value = s;
                return !string.IsNullOrWhiteSpace(value);
            case JsonElement je when je.ValueKind == JsonValueKind.String:
                value = je.GetString() ?? string.Empty;
                return !string.IsNullOrWhiteSpace(value);
        }

        return false;
    }

    private static List<int> NormalizeFragmentSizes(IEnumerable<int> input)
    {
        return input
            .Where(v => v > 0)
            .Select(v => Math.Max(4, v))
            .Take(4)
            .ToList();
    }

    private static List<int>? TryParseIntArrayFromJsonElement(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        var result = new List<int>();
        foreach (var item in element.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.Number && item.TryGetInt32(out var v))
            {
                result.Add(v);
                continue;
            }

            if (item.ValueKind == JsonValueKind.String && int.TryParse(item.GetString(), out var parsed))
            {
                result.Add(parsed);
                continue;
            }
        }

        return result;
    }

    private static List<int>? TryParseIntArrayFromString(string s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;

        var parts = s.Split(new[] { ',', ';', '/', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        var result = new List<int>();
        foreach (var part in parts)
        {
            if (int.TryParse(part, out var v))
            {
                result.Add(v);
            }
        }

        return result;
    }

    private static List<int>? TryParseIntArrayFromObjects(IEnumerable<object> obj)
    {
        var result = new List<int>();

        foreach (var item in obj)
        {
            switch (item)
            {
                case int i:
                    result.Add(i);
                    break;
                case long l when l is <= int.MaxValue and >= int.MinValue:
                    result.Add((int)l);
                    break;
                case string s when int.TryParse(s, out var parsed):
                    result.Add(parsed);
                    break;
                case JsonElement je when je.ValueKind == JsonValueKind.Number && je.TryGetInt32(out var v):
                    result.Add(v);
                    break;
            }
        }

        return result;
    }
}

using System;
using IspAudit.Core.Intelligence.Feedback;

namespace IspAudit.Utils;

/// <summary>
/// Единая точка доступа к feedback store для INTEL.
/// Хранится в state/ рядом с приложением, чтобы работать в portable-режиме.
/// </summary>
internal static class FeedbackStoreProvider
{
    private static readonly object Gate = new();
    private static IFeedbackStore? _store;

    public static IFeedbackStore? TryGetStore(Action<string>? log = null)
    {
        try
        {
            // Двойная проверка, чтобы не брать lock на горячем пути (селектор вызывается часто).
            var s = _store;
            if (s != null) return s;

            lock (Gate)
            {
                if (_store != null) return _store;

                AppPaths.EnsureStateDirectoryExists();
                var path = AppPaths.GetStateFilePath("feedback_store.json");

                _store = new JsonFileFeedbackStore(path);
                log?.Invoke($"[FEEDBACK] store enabled: {path}");

                return _store;
            }
        }
        catch (Exception ex)
        {
            log?.Invoke($"[FEEDBACK] store disabled: {ex.Message}");
            return null;
        }
    }
}

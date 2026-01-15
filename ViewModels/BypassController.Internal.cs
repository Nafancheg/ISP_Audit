using System;
using System.Collections.Generic;
using System.ComponentModel;
using IspAudit.Bypass;
using IspAudit.Utils;

namespace IspAudit.ViewModels
{
    public partial class BypassController
    {
        private void CheckCompatibility()
        {
            var warnings = new List<string>();

            // Fragment + Disorder = взаимоисключающие
            if (IsFragmentEnabled && IsDisorderEnabled)
            {
                warnings.Add("⚠️ Fragment + Disorder — выберите одну из стратегий фрагментации");
            }

            // Fake без фрагментации — менее эффективно
            if (IsFakeEnabled && !IsFragmentEnabled && !IsDisorderEnabled)
            {
                warnings.Add("ℹ️ Fake без фрагментации — рекомендуется добавить Fragment или Disorder");
            }

            // DoH без других опций — только DNS защита
            if (IsDoHEnabled && !IsFragmentEnabled && !IsDisorderEnabled && !IsFakeEnabled && !IsDropRstEnabled)
            {
                warnings.Add("ℹ️ Только DoH — защищает DNS, но DPI может блокировать трафик");
            }

            // Только DROP RST без фрагментации — частичная защита
            if (IsDropRstEnabled && !IsFragmentEnabled && !IsDisorderEnabled && !IsFakeEnabled)
            {
                warnings.Add("ℹ️ Только DROP RST — защита от RST-инъекций, но SNI виден DPI");
            }

            CompatibilityWarning = warnings.Count > 0 ? string.Join("\n", warnings) : "";
        }

        private void CheckVpnStatus()
        {
            try
            {
                if (NetUtils.LikelyVpnActive())
                {
                    IsVpnDetected = true;
                    VpnWarningText = "🔒 Обнаружен VPN — bypass может быть не нужен или конфликтовать с VPN";
                    Log("[VPN] VPN detected - bypass may conflict");
                }
                else
                {
                    IsVpnDetected = false;
                    VpnWarningText = "";
                }
            }
            catch (Exception ex)
            {
                Log($"[VPN] Error checking VPN status: {ex.Message}");
            }
        }

        private void UpdateBypassWarning()
        {
            // TODO: Check if RST blocking is actually active in TrafficEngine
            // For now, assume it works if enabled
            BypassWarningText = "";
        }

        private void NotifyActiveStatesChanged()
        {
            OnPropertyChanged(nameof(CurrentBypassStrategy));
            OnPropertyChanged(nameof(IsTlsFragmentActive));
            OnPropertyChanged(nameof(IsTlsDisorderActive));
            OnPropertyChanged(nameof(IsTlsFakeActive));
            OnPropertyChanged(nameof(IsDropRstActive));
        }

        private void PersistFragmentPreset()
        {
            // Сохраняем только параметры фрагментации/пресета, чтобы не перетирать другие поля профиля
            // (например, TTL trick/AutoTTL, redirect rules и будущие расширения).
            BypassProfile.TryUpdateFragmentSettings(
                _currentOptions.FragmentSizes,
                _currentOptions.PresetName,
                _currentOptions.AutoAdjustAggressive);
        }

        private void PersistAssistSettings()
        {
            BypassProfile.TryUpdateAssistSettings(
                _currentOptions.AllowNoSni,
                _currentOptions.DropUdp443,
                _currentOptions.DropUdp443Global);
        }

        private void Log(string message)
        {
            OnLog?.Invoke(message);
        }

        private void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}

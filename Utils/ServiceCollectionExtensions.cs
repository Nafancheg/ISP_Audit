using System;
using Microsoft.Extensions.DependencyInjection;
using IspAudit.ViewModels;
using IspAudit.Bypass;
using IspAudit.Core.Bypass;
using IspAudit.Core.Traffic;
using IspAudit.Core.Interfaces;

namespace IspAudit.Utils
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddIspAuditServices(this IServiceCollection services)
        {
            if (services == null) throw new ArgumentNullException(nameof(services));

            services.AddSingleton<NoiseHostFilter>();

            // Единый фильтр трафика (дедуп/шум/правила UI). Важно: использует тот же NoiseHostFilter singleton.
            services.AddSingleton<ITrafficFilter, UnifiedTrafficFilter>();

            // Auto-hostlist (UI + pipeline) должен быть единым, иначе будут расхождения по кандидатам.
            services.AddSingleton<AutoHostlistService>();

            // Core runtime: единый движок перехвата.
            services.AddSingleton<TrafficEngine>(sp => new TrafficEngine(progress: new Progress<string>(MainViewModel.Log)));

            // Единый владелец состояния bypass поверх TrafficEngine.
            services.AddSingleton<BypassStateManager>(sp =>
                BypassStateManager.GetOrCreate(
                    sp.GetRequiredService<TrafficEngine>(),
                    baseProfile: null,
                    log: MainViewModel.Log));

            // P0.1: единый источник истины по group participation/pinning.
            services.AddSingleton<GroupBypassAttachmentStore>();

            // UI/VM сервисы (создаются DI и переиспользуются весь срок приложения).
            services.AddSingleton<BypassController>(sp =>
                new BypassController(
                    sp.GetRequiredService<BypassStateManager>(),
                    sp.GetRequiredService<AutoHostlistService>()));
            services.AddSingleton<DiagnosticOrchestrator>(sp =>
                new DiagnosticOrchestrator(
                    sp.GetRequiredService<BypassStateManager>(),
                    sp.GetRequiredService<NoiseHostFilter>()));
            services.AddSingleton<TestResultsManager>();

            services.AddSingleton<MainViewModel>();

            // Для OperatorWindow сохраняем контракт Func<MainViewModel>.
            services.AddSingleton<Func<MainViewModel>>(sp => () => sp.GetRequiredService<MainViewModel>());

            return services;
        }
    }
}

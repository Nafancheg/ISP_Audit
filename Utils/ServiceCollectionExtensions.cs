using System;
using Microsoft.Extensions.DependencyInjection;
using IspAudit.ViewModels;
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

            services.AddSingleton<MainViewModel>();

            // Для OperatorWindow сохраняем контракт Func<MainViewModel>.
            services.AddSingleton<Func<MainViewModel>>(sp => () => sp.GetRequiredService<MainViewModel>());

            return services;
        }
    }
}

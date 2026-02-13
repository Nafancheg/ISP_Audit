using System;
using Microsoft.Extensions.DependencyInjection;
using IspAudit.ViewModels;

namespace IspAudit.Utils
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddIspAuditServices(this IServiceCollection services)
        {
            if (services == null) throw new ArgumentNullException(nameof(services));

            services.AddSingleton<NoiseHostFilter>();

            services.AddSingleton<MainViewModel>();

            // Для OperatorWindow сохраняем контракт Func<MainViewModel>.
            services.AddSingleton<Func<MainViewModel>>(sp => () => sp.GetRequiredService<MainViewModel>());

            return services;
        }
    }
}

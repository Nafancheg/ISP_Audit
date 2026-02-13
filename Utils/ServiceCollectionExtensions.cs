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

            // ВАЖНО: NoiseHostFilter пока остаётся совместимым со старым singleton-путём.
            // Регистрируем единый экземпляр, чтобы DI и legacy-код ссылались на один объект.
            services.AddSingleton(_ => NoiseHostFilter.Instance);

            services.AddSingleton<MainViewModel>();

            // Для OperatorWindow сохраняем контракт Func<MainViewModel>.
            services.AddSingleton<Func<MainViewModel>>(sp => () => sp.GetRequiredService<MainViewModel>());

            return services;
        }
    }
}

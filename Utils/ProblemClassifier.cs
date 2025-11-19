using System;
using System.Collections.Generic;
using System.Linq;
using ISPAudit.Models;

namespace IspAudit.Utils
{
    /// <summary>
    /// Классификатор проблем подключения на основе результатов тестов
    /// </summary>
    internal static class ProblemClassifier
    {
        /// <summary>
        /// Анализирует результаты тестов и возвращает набор обнаруженных блокировок
        /// </summary>
        public static List<BlockageProblem> ClassifyProblems(List<TestResult> testResults)
        {
            var problems = new List<BlockageProblem>();

            // Группируем результаты по целям (Target)
            var targetGroups = testResults
                .Where(r => r.Target != null)
                .GroupBy(r => r.Target!.Host)
                .ToList();

            foreach (var group in targetGroups)
            {
                var target = group.First().Target!;
                var results = group.ToList();

                // Анализируем каждую цель
                var targetProblems = AnalyzeTarget(target, results);
                problems.AddRange(targetProblems);
            }

            // Удаляем дубликаты по типу блокировки
            return problems
                .GroupBy(p => p.Type)
                .Select(g => g.First())
                .OrderByDescending(p => p.Severity)
                .ToList();
        }

        /// <summary>
        /// Анализирует результаты тестов для одной цели
        /// </summary>
        private static List<BlockageProblem> AnalyzeTarget(Target target, List<TestResult> results)
        {
            var problems = new List<BlockageProblem>();

            // Используем Details для определения типа теста (содержит информацию о порте, протоколе)
            var failedResults = results.Where(r => r.Status == TestStatus.Fail).ToList();
            
            if (!failedResults.Any())
                return problems;

            // Анализ ошибок по их описанию
            foreach (var result in failedResults)
            {
                var error = result.Error?.ToLowerInvariant() ?? "";
                var details = result.Details?.ToLowerInvariant() ?? "";

                // 1. DNS Filtering
                if (error.Contains("dns") && (error.Contains("filtered") || error.Contains("bogus") || error.Contains("подмен")))
                {
                    if (!problems.Any(p => p.Type == BlockageType.DnsFiltering && p.Target == target.Host))
                    {
                        problems.Add(new BlockageProblem
                        {
                            Type = BlockageType.DnsFiltering,
                            Target = target.Host,
                            Description = $"DNS блокировка для {target.Name}: {result.Error}",
                            Severity = ProblemSeverity.Critical,
                            Evidence = result.Error ?? ""
                        });
                    }
                }
                // 2. DPI RST Injection
                else if (error.Contains("rst") || details.Contains("rst"))
                {
                    if (!problems.Any(p => p.Type == BlockageType.DpiRstInjection && p.Target == target.Host))
                    {
                        problems.Add(new BlockageProblem
                        {
                            Type = BlockageType.DpiRstInjection,
                            Target = target.Host,
                            Description = $"DPI RST injection для {target.Name}: соединение разрывается",
                            Severity = ProblemSeverity.High,
                            Evidence = result.Error ?? ""
                        });
                    }
                }
                // 3. TLS SNI Filtering
                else if (error.Contains("tls") || error.Contains("ssl") || error.Contains("handshake"))
                {
                    if (!problems.Any(p => p.Type == BlockageType.TlsSniFiltering && p.Target == target.Host))
                    {
                        problems.Add(new BlockageProblem
                        {
                            Type = BlockageType.TlsSniFiltering,
                            Target = target.Host,
                            Description = $"TLS SNI фильтрация для {target.Name}: блокировка по имени хоста",
                            Severity = ProblemSeverity.High,
                            Evidence = result.Error ?? ""
                        });
                    }
                }
                // 4. Firewall Block
                else if (error.Contains("timeout") || error.Contains("refused") || error.Contains("таймаут"))
                {
                    if (!problems.Any(p => p.Type == BlockageType.FirewallBlock && p.Target == target.Host))
                    {
                        problems.Add(new BlockageProblem
                        {
                            Type = BlockageType.FirewallBlock,
                            Target = target.Host,
                            Description = $"Firewall блокировка для {target.Name}: порт недоступен",
                            Severity = ProblemSeverity.Medium,
                            Evidence = result.Error ?? ""
                        });
                    }
                }
                // 5. UDP Block
                else if (details.Contains("udp"))
                {
                    if (!problems.Any(p => p.Type == BlockageType.UdpBlock && p.Target == target.Host))
                    {
                        problems.Add(new BlockageProblem
                        {
                            Type = BlockageType.UdpBlock,
                            Target = target.Host,
                            Description = $"UDP блокировка для {target.Name}: пакеты не доходят",
                            Severity = ProblemSeverity.Medium,
                            Evidence = result.Error ?? ""
                        });
                    }
                }
            }

            return problems;
        }

        // Удаляем неиспользуемые методы эвристик
    }

    /// <summary>
    /// Тип обнаруженной блокировки
    /// </summary>
    public enum BlockageType
    {
        /// <summary>DNS фильтрация (подмена или отсутствие ответов)</summary>
        DnsFiltering,
        
        /// <summary>DPI RST injection при TLS handshake</summary>
        DpiRstInjection,
        
        /// <summary>Фильтрация по TLS SNI</summary>
        TlsSniFiltering,
        
        /// <summary>Firewall блокировка портов</summary>
        FirewallBlock,
        
        /// <summary>UDP блокировка</summary>
        UdpBlock,
        
        /// <summary>HTTP фильтрация (по URL/заголовкам)</summary>
        HttpFiltering,
        
        /// <summary>Неизвестная проблема</summary>
        Unknown
    }

    /// <summary>
    /// Серьезность проблемы
    /// </summary>
    public enum ProblemSeverity
    {
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    }

    /// <summary>
    /// Описание обнаруженной проблемы блокировки
    /// </summary>
    public class BlockageProblem
    {
        /// <summary>Тип блокировки</summary>
        public required BlockageType Type { get; init; }
        
        /// <summary>Целевой хост</summary>
        public required string Target { get; init; }
        
        /// <summary>Описание проблемы</summary>
        public required string Description { get; init; }
        
        /// <summary>Серьезность</summary>
        public required ProblemSeverity Severity { get; init; }
        
        /// <summary>Доказательства (статусы тестов)</summary>
        public string? Evidence { get; init; }
    }
}

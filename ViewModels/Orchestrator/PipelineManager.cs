using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using IspAudit.Core.Intelligence.Contracts;
using IspAudit.Core.Models;
using IspAudit.Utils;

using Application = System.Windows.Application;

namespace IspAudit.ViewModels.Orchestrator;

internal sealed class PipelineManager
{
    public Progress<string> CreateUiProgress(Action<string> onUiMessage)
    {
        if (onUiMessage == null) throw new ArgumentNullException(nameof(onUiMessage));

        return new Progress<string>(msg =>
        {
            Application.Current?.Dispatcher.BeginInvoke(() => onUiMessage(msg));
        });
    }

    public void AttachPlanBuiltListener(LiveTestingPipeline pipeline, Action<string, BypassPlan> onPlanBuilt)
    {
        if (pipeline == null) throw new ArgumentNullException(nameof(pipeline));
        if (onPlanBuilt == null) throw new ArgumentNullException(nameof(onPlanBuilt));

        pipeline.OnPlanBuilt += (hostKey, plan) =>
        {
            Application.Current?.Dispatcher.BeginInvoke(() => onPlanBuilt(hostKey, plan));
        };
    }

    public async Task DrainPendingHostsAsync(
        ConcurrentQueue<HostDiscovered> queue,
        LiveTestingPipeline pipeline,
        LiveTestingPipeline.HostPriority priority = LiveTestingPipeline.HostPriority.Low)
    {
        if (queue == null) throw new ArgumentNullException(nameof(queue));
        if (pipeline == null) throw new ArgumentNullException(nameof(pipeline));

        while (queue.TryDequeue(out var host))
        {
            await pipeline.EnqueueHostAsync(host, priority).ConfigureAwait(false);
        }
    }
}

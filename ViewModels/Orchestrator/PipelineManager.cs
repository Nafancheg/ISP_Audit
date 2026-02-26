using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using IspAudit.Core.Intelligence.Contracts;
using IspAudit.Core.Models;
using IspAudit.Utils;

namespace IspAudit.ViewModels.Orchestrator;

internal sealed class PipelineManager
{
    private Action<Action> _dispatchToUi;

    public PipelineManager(Action<Action>? dispatchToUi = null)
    {
        _dispatchToUi = dispatchToUi ?? (action => action());
    }

    public void ConfigureUiDispatcher(Action<Action>? dispatchToUi)
    {
        _dispatchToUi = dispatchToUi ?? (action => action());
    }

    private void DispatchToUi(Action action)
    {
        if (action == null) return;

        try
        {
            _dispatchToUi(action);
        }
        catch
        {
            action();
        }
    }

    public Progress<string> CreateUiProgress(Action<string> onUiMessage)
    {
        if (onUiMessage == null) throw new ArgumentNullException(nameof(onUiMessage));

        return new Progress<string>(msg =>
        {
            DispatchToUi(() => onUiMessage(msg));
        });
    }

    public void AttachPlanBuiltListener(LiveTestingPipeline pipeline, Action<string, BypassPlan> onPlanBuilt)
    {
        if (pipeline == null) throw new ArgumentNullException(nameof(pipeline));
        if (onPlanBuilt == null) throw new ArgumentNullException(nameof(onPlanBuilt));

        pipeline.OnPlanBuilt += (hostKey, plan) =>
        {
            DispatchToUi(() => onPlanBuilt(hostKey, plan));
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

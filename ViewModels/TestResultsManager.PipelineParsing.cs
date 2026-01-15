using System;

namespace IspAudit.ViewModels
{
    public partial class TestResultsManager
    {
        /// <summary>
        /// Парсинг сообщений от pipeline
        /// </summary>
        public void ParsePipelineMessage(string msg)
        {
            PipelineParser.Parse(msg);
        }
    }
}

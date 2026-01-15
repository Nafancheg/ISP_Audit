using System.Windows.Input;

namespace IspAudit.ViewModels
{
    public partial class MainViewModel
    {
        #region Commands

        public ICommand StartCommand { get; }
        public ICommand StartLiveTestingCommand { get; }
        public ICommand CancelCommand { get; }
        public ICommand SetStateCommand { get; }
        public ICommand ReportCommand { get; }
        public ICommand DetailsCommand { get; }
        public ICommand BrowseExeCommand { get; }
        public ICommand ToggleThemeCommand { get; }

        // Bypass Toggle Commands
        public ICommand ToggleFragmentCommand { get; }
        public ICommand ToggleDisorderCommand { get; }
        public ICommand ToggleFakeCommand { get; }
        public ICommand ToggleDropRstCommand { get; }
        public ICommand ToggleDoHCommand { get; }
        public ICommand DisableAllBypassCommand { get; }
        public ICommand ApplyRecommendationsCommand { get; }
        public ICommand ApplyDomainRecommendationsCommand { get; }
        public ICommand RestartConnectionCommand { get; }
        public ICommand ConnectFromResultCommand { get; }

        // P0.6: Network change staged revalidation
        public ICommand NetworkRevalidateCommand { get; }
        public ICommand NetworkDisableBypassCommand { get; }
        public ICommand NetworkIgnoreCommand { get; }

        #endregion
    }
}

import React from 'react';

const ControlPanel = ({
    onTrainModel,
    onTrainRealData,
    onTestDetection,
    onTestRealDetection,
    onGenerateData,
    isLoading,
    modelTrained,
    realDataEnabled
}) => {
    const basicButtons = [
        {
            id: 'train-basic',
            label: 'Train Basic AI',
            icon: 'bi-mortarboard',
            variant: 'btn-primary',
            onClick: onTrainModel,
            disabled: isLoading,
            loadingText: 'Training Basic AI...',
            description: 'Train with generated sample data (quick demo)'
        },
        {
            id: 'test-basic',
            label: 'Test Basic Detection',
            icon: 'bi-search',
            variant: 'btn-success',
            onClick: onTestDetection,
            disabled: isLoading || !modelTrained,
            loadingText: 'Testing Basic Detection...',
            description: 'Test with sample log data'
        },
        {
            id: 'generate',
            label: 'Generate Sample Data',
            icon: 'bi-database',
            variant: 'btn-info',
            onClick: onGenerateData,
            disabled: isLoading,
            loadingText: 'Generating Data...',
            description: 'Create sample log data for testing'
        }
    ];

    const advancedButtons = [
        {
            id: 'train-real',
            label: 'Train on Real Linux Data',
            icon: 'bi-shield-check',
            variant: 'btn-primary',
            onClick: onTrainRealData,
            disabled: isLoading,
            loadingText: 'Training on Real Data...',
            description: 'Train AI using authentic Linux system logs'
        },
        {
            id: 'test-real',
            label: 'Test Real Detection',
            icon: 'bi-bug',
            variant: 'btn-danger',
            onClick: onTestRealDetection,
            disabled: isLoading || !modelTrained,
            loadingText: 'Analyzing Real Logs...',
            description: 'Detect threats in production Linux logs'
        },
        {
            id: 'test-basic-alt',
            label: 'Test Sample Detection',
            icon: 'bi-play-circle',
            variant: 'btn-success',
            onClick: onTestDetection,
            disabled: isLoading || !modelTrained,
            loadingText: 'Testing Sample Data...',
            description: 'Quick test with generated sample data'
        }
    ];

    const buttonsToShow = realDataEnabled ? advancedButtons : basicButtons;

    return (
        <div className="row mb-4">
            <div className="col-12">
                <div className="card shadow">
                    <div className="card-header bg-light">
                        <h5 className="mb-0 d-flex align-items-center">
                            <i className="bi bi-gear-fill me-2 text-primary"></i>
                            {realDataEnabled ? 'Advanced Control Panel - Real Data Mode' : 'Basic Control Panel - Sample Data Mode'}
                        </h5>
                    </div>
                    <div className="card-body">
                        <div className="row g-3">
                            {buttonsToShow.map((button) => (
                                <div key={button.id} className="col-lg-4 col-md-6">
                                    <div className="d-grid">
                                        <button
                                            className={`btn ${button.variant} btn-lg`}
                                            onClick={button.onClick}
                                            disabled={button.disabled}
                                        >
                                            <i className={`${button.icon} me-2`}></i>
                                            {isLoading && !button.disabled ? button.loadingText : button.label}
                                        </button>
                                        <small className="text-muted mt-1 text-center">
                                            {button.description}
                                        </small>
                                    </div>
                                </div>
                            ))}
                        </div>

                        {/* Loading Progress Bar */}
                        {isLoading && (
                            <div className="mt-4">
                                <div className="progress">
                                    <div className="progress-bar progress-bar-striped progress-bar-animated bg-primary"
                                        role="progressbar"
                                        style={{ width: '100%' }}>
                                    </div>
                                </div>
                                <div className="d-flex justify-content-between mt-2">
                                    <small className="text-muted">
                                        {realDataEnabled ? 'Processing real Linux system logs...' : 'Processing sample data...'}
                                    </small>
                                    <small className="text-muted">
                                        <i className="bi bi-hourglass-split"></i>
                                    </small>
                                </div>
                            </div>
                        )}

                        {/* Status Messages */}
                        {!modelTrained && !isLoading && (
                            <div className="alert alert-warning mt-3 mb-0" role="alert">
                                <div className="d-flex align-items-center">
                                    <i className="bi bi-exclamation-triangle-fill me-2"></i>
                                    <div>
                                        <strong>AI Model Not Trained</strong>
                                        <br />
                                        <small>
                                            {realDataEnabled ?
                                                'Train on real Linux data for production-grade threat detection' :
                                                'Train the basic AI model first before running detection tests'}
                                        </small>
                                    </div>
                                </div>
                            </div>
                        )}

                        {modelTrained && !isLoading && (
                            <div className="alert alert-success mt-3 mb-0" role="alert">
                                <div className="d-flex align-items-center">
                                    <i className="bi bi-check-circle-fill me-2"></i>
                                    <div>
                                        <strong>
                                            {realDataEnabled ? 'Advanced AI Ready' : 'Basic AI Ready'}
                                        </strong>
                                        <br />
                                        <small>
                                            {realDataEnabled ?
                                                'Your ensemble models are trained on real Linux logs and ready for threat detection!' :
                                                'Your basic anomaly detection model is ready for testing with sample data!'}
                                        </small>
                                    </div>
                                </div>
                            </div>
                        )}

                        {realDataEnabled && (
                            <div className="mt-3">
                                <div className="alert alert-info mb-0" role="alert">
                                    <div className="d-flex align-items-center">
                                        <i className="bi bi-info-circle-fill me-2"></i>
                                        <div>
                                            <strong>Enterprise-Grade Capabilities Enabled</strong>
                                            <br />
                                            <small>
                                                Using real Linux system logs with advanced ensemble ML models (Isolation Forest + One-Class SVM)
                                            </small>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default ControlPanel;

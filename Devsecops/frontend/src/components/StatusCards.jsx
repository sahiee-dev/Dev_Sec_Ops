import React from 'react';

const StatusCards = ({ stats, modelTrained, realDataEnabled, realTimeStats }) => {
    // Use real-time stats when available, fallback to regular stats
    const displayStats = realTimeStats && realTimeStats.total_logs_processed > 0 ? {
        totalLogs: realTimeStats.total_logs_processed,
        normalCount: realTimeStats.total_logs_processed - realTimeStats.total_anomalies_detected,
        suspiciousCount: realTimeStats.total_anomalies_detected
    } : stats;

    const cards = [
        {
            title: 'Total Logs Analyzed',
            value: displayStats.totalLogs.toLocaleString(),
            icon: 'bi-file-earmark-text-fill',
            bgColor: 'bg-primary',
            textColor: 'text-white'
        },
        {
            title: 'Normal Activities',
            value: displayStats.normalCount.toLocaleString(),
            icon: 'bi-check-circle-fill',
            bgColor: 'bg-success',
            textColor: 'text-white'
        },
        {
            title: 'Suspicious Activities',
            value: displayStats.suspiciousCount.toLocaleString(),
            icon: 'bi-exclamation-triangle-fill',
            bgColor: displayStats.suspiciousCount > 0 ? 'bg-danger' : 'bg-warning',
            textColor: 'text-white'
        },
        {
            title: realDataEnabled ? 'Advanced AI Status' : 'Basic AI Status',
            value: modelTrained ? (realDataEnabled ? 'Real Data Trained' : 'Sample Data Trained') : 'Not Trained',
            icon: modelTrained ? (realDataEnabled ? 'bi-shield-check' : 'bi-cpu-fill') : 'bi-cpu',
            bgColor: modelTrained ? (realDataEnabled ? 'bg-success' : 'bg-info') : 'bg-secondary',
            textColor: 'text-white'
        },
    ];

    return (
        <div className="row mb-4">
            {cards.map((card, index) => (
                <div key={index} className="col-lg-3 col-md-6 mb-3">
                    <div className={`card ${card.bgColor} ${card.textColor} h-100 shadow-sm`}>
                        <div className="card-body">
                            <div className="d-flex justify-content-between align-items-center">
                                <div>
                                    <h6 className="card-title mb-1 opacity-75">{card.title}</h6>
                                    <h4 className="mb-0 fw-bold">{card.value}</h4>
                                    {realTimeStats && realTimeStats.total_logs_processed > 0 && (
                                        <small className="opacity-75">
                                            {realTimeStats.threat_rate_percent}% threat rate
                                        </small>
                                    )}
                                </div>
                                <div className="text-end">
                                    <i className={`${card.icon} fs-1 opacity-75`}></i>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            ))}
        </div>
    );
};

export default StatusCards;

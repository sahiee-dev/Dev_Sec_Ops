import React from 'react';

const Navbar = ({ systemStatus }) => {
    return (
        <nav className="navbar navbar-expand-lg navbar-dark bg-dark shadow">
            <div className="container-fluid">
                <a className="navbar-brand fw-bold" href="#" onClick={(e) => e.preventDefault()}>
                    <i className="bi bi-shield-check me-2"></i>
                    DevSecOps Anomaly Detection
                </a>
                <div className="navbar-nav ms-auto">
                    <span className="nav-link d-flex align-items-center">
                        <i className={`bi bi-circle-fill me-2 ${systemStatus.online ? 'text-success' : 'text-danger'}`}></i>
                        <span className="badge bg-secondary">
                            {systemStatus.online ? 'System Online' : 'System Offline'}
                        </span>
                    </span>
                </div>
            </div>
        </nav>
    );
};

export default Navbar;

#!/usr/bin/env python3
"""
PyADRecon Dashboard Generator
Generates an interactive HTML dashboard from CSV outputs
"""

import os
import csv
import json
import base64
from datetime import datetime
from pathlib import Path


class DashboardGenerator:
    """Generate interactive HTML dashboard from PyADRecon CSV outputs."""
    
    def __init__(self, csv_dir: str, output_file: str = None):
        self.csv_dir = Path(csv_dir)
        self.output_file = output_file or str(self.csv_dir.parent / "dashboard.html")
        self.data = {}
        
    def load_csv_data(self):
        """Load all CSV files into memory."""
        csv_files = list(self.csv_dir.glob("*.csv"))
        
        for csv_file in csv_files:
            module_name = csv_file.stem
            try:
                with open(csv_file, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    self.data[module_name] = list(reader)
            except Exception as e:
                print(f"Warning: Could not load {csv_file.name}: {e}")
        
        return len(self.data) > 0
    
    def generate_html(self):
        """Generate the complete HTML dashboard."""
        
        # Embed data as JavaScript
        data_json = json.dumps(self.data, indent=2)
        
        # Get generation timestamp
        generation_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PyADRecon Dashboard</title>
    
    <!-- Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>
    
    <!-- Vue.js 3 -->
    <script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>
    
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.js"></script>
    
    <!-- Vis.js Network for graph visualization -->
    <script src="https://unpkg.com/vis-network@9.1.6/standalone/umd/vis-network.min.js"></script>
    <link href="https://unpkg.com/vis-network@9.1.6/styles/vis-network.min.css" rel="stylesheet" />
    
    <!-- Font Awesome for icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" />
    
    <style>
        [v-cloak] {{ display: none; }}
        
        /* Dark mode styles */
        body.dark {{
            background-color: #0f172a;
            color: #f1f5f9;
        }}
        
        .dark .bg-white {{
            background-color: #1e293b;
            color: #f1f5f9;
        }}
        
        .dark .bg-gray-50 {{
            background-color: #0f172a;
        }}
        
        .dark .text-gray-900 {{
            color: #f1f5f9;
        }}
        
        .dark .text-gray-600 {{
            color: #cbd5e1;
        }}
        
        .dark .text-gray-500 {{
            color: #94a3b8;
        }}
        
        .dark .border-gray-200 {{
            border-color: #334155;
        }}
        
        .dark .bg-gray-800 {{
            background-color: #1e293b;
        }}
        
        .dark .bg-gray-700 {{
            background-color: #334155;
        }}
        
        .dark .divide-gray-200 {{
            border-color: #334155;
        }}
        
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 0.375rem;
            font-weight: 600;
            font-size: 0.75rem;
            text-transform: uppercase;
        }}
        
        .badge-critical {{
            background-color: #7f1d1d;
            color: white;
        }}
        
        .badge-high {{
            background-color: #dc2626;
            color: white;
        }}
        
        .badge-medium {{
            background-color: #f97316;
            color: white;
        }}
        
        .badge-low {{
            background-color: #fbbf24;
            color: #78350f;
        }}
        
        .badge-none {{
            background-color: #6b7280;
            color: white;
        }}
        
        .badge-purple {{
            background-color: #9333ea;
            color: white;
        }}
        
        .badge-cyan {{
            background-color: #06b6d4;
            color: white;
        }}
        
        .badge-amber {{
            background-color: #f59e0b;
            color: white;
        }}
        
        .badge-pink {{
            background-color: #ec4899;
            color: white;
        }}
        
        .badge-indigo {{
            background-color: #6366f1;
            color: white;
        }}
        
        .stat-card {{
            transition: transform 0.2s, box-shadow 0.2s;
            cursor: pointer;
        }}
        
        .stat-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
        }}
        
        .table-container {{
            max-height: 600px;
            overflow-y: auto;
        }}
        
        table {{
            border-collapse: collapse;
            width: 100%;
        }}
        
        th {{
            position: sticky;
            top: 0;
            background-color: #f3f4f6;
            z-index: 10;
            cursor: pointer;
            user-select: none;
            padding: 0.75rem 1.5rem;
            font-weight: 600;
        }}
        
        .dark th {{
            background-color: #1e293b;
            color: #f1f5f9;
            border-bottom: 2px solid #334155;
        }}
        
        tbody tr {{
            border-bottom: 1px solid #e5e7eb;
        }}
        
        .dark tbody tr {{
            border-bottom: 1px solid #334155;
        }}
        
        tr:hover {{
            background-color: #f9fafb;
        }}
        
        .dark tr:hover {{
            background-color: #334155;
        }}
        
        td {{
            padding: 0.75rem 1.5rem;
            color: #1f2937;
        }}
        
        .dark td {{
            color: #e2e8f0;
        }}
        
        /* Improve text contrast in dark mode */
        .dark input,
        .dark select {{
            background-color: #1e293b;
            border-color: #475569;
            color: #f1f5f9;
        }}
        
        .dark input::placeholder {{
            color: #64748b;
        }}
        
        /* Card backgrounds */
        .dark .stat-card {{
            background-color: #1e293b;
            border: 1px solid #334155;
        }}
        
        #trustGraph {{
            height: 500px;
            border: 1px solid #e5e7eb;
            border-radius: 0.5rem;
        }}
        
        .dark #trustGraph {{
            border-color: #4a5568;
        }}
        
        .search-input {{
            transition: all 0.3s;
        }}
        
        .search-input:focus {{
            transform: scale(1.02);
        }}
        
        /* Loading indicator */
        .loading-message {{
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            display: none;
        }}
        
        .loading-message.show {{
            display: block;
        }}
        
        /* Inline tool links - inherit color, no underline, subtle hover */
        .tool-link {{
            color: inherit;
            text-decoration: none;
            border-bottom: 1px dotted currentColor;
            transition: opacity 0.2s;
        }}
        
        .tool-link:hover {{
            opacity: 0.7;
        }}
    </style>
</head>
<body class="bg-gray-900 dark">
    <div id="app" v-cloak>
        <!-- Header -->
        <header class="bg-white dark:bg-gray-800 shadow-lg sticky top-0 z-50">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
                <div class="flex justify-between items-center">
                    <div>
                        <h1 class="text-3xl font-bold text-white">
                            <i class="fas fa-shield-halved text-blue-600"></i>
                            PyADRecon Dashboard
                        </h1>
                        <div class="flex gap-4 text-sm text-gray-400 mt-2">
                            <span v-if="aboutInfo.version">
                                <i class="fas fa-code-branch"></i> {{{{ aboutInfo.version }}}}
                            </span>
                            <span v-if="aboutInfo.domain">
                                <i class="fas fa-network-wired"></i> Target: {{{{ aboutInfo.domain }}}}
                            </span>
                            <span v-if="aboutInfo.user">
                                <i class="fas fa-user"></i> Executed by: {{{{ aboutInfo.user }}}}
                            </span>
                            <span v-if="aboutInfo.computer">
                                <i class="fas fa-desktop"></i> From: {{{{ aboutInfo.computer }}}}
                            </span>
                            <span>
                                <i class="fas fa-clock"></i> Generated: {generation_timestamp}
                            </span>
                        </div>
                    </div>
                    <div class="flex gap-4 items-center">
                        <a v-if="aboutInfo.github" :href="'https://' + aboutInfo.github" target="_blank"
                           class="px-4 py-2 rounded-lg bg-gray-700 text-white hover:bg-gray-600 transition"
                           title="View on GitHub">
                            <i class="fab fa-github"></i>
                        </a>
                        <a :href="'vulnad_local-Report.xlsx'" download
                           class="px-4 py-2 rounded-lg bg-green-600 text-white hover:bg-green-700 transition">
                            <i class="fas fa-file-excel"></i> Download XLSX
                        </a>
                    </div>
                </div>
            </div>
        </header>

        <!-- Navigation Tabs -->
        <nav class="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 sticky top-20 z-40">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div class="flex space-x-8">
                    <button v-for="tab in tabs" :key="tab.id"
                            @click="activeTab = tab.id"
                            :class="[
                                'py-4 px-1 border-b-2 font-medium text-sm transition',
                                activeTab === tab.id 
                                    ? 'border-blue-500 text-blue-600 dark:text-blue-400' 
                                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                            ]">
                        <i :class="tab.icon"></i> {{{{ tab.label }}}} 
                        <span v-if="tab.id === 'findings' && securityIssuesCount > 0" class="ml-2 px-2 py-1 text-xs rounded-full bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200">
                            {{{{ securityIssuesCount }}}}
                        </span>
                        <span v-else-if="tab.count" class="ml-2 px-2 py-1 text-xs rounded-full bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200">
                            {{{{ tab.count }}}}
                        </span>
                    </button>
                </div>
            </div>
        </nav>

        <!-- Main Content -->
        <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            
            <!-- Overview Tab -->
            <div v-if="activeTab === 'overview'" class="space-y-6">
                <!-- Security Findings Tiles -->
                <div class="mb-6">
                    <h3 class="text-lg font-semibold text-gray-700 dark:text-gray-300 mb-3">
                        <i class="fas fa-shield-virus"></i> Security Findings
                    </h3>
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                    <div v-if="vulnerableCertTemplates.length > 0" @click="navigateToSection('findings', 'adcs-templates-section')" class="stat-card bg-white dark:bg-gray-800 rounded-lg shadow p-6 cursor-pointer hover:shadow-lg transition-shadow">
                            <div class="flex items-center">
                                <div class="flex-shrink-0 bg-orange-100 dark:bg-orange-900/30 rounded-md p-3">
                                    <i class="fas fa-certificate text-orange-600 text-2xl"></i>
                                </div>
                                <div class="ml-5 w-0 flex-1">
                                    <dl>
                                        <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">ESC Vulnerable</dt>
                                        <dd class="text-3xl font-semibold text-gray-900 dark:text-white">{{{{ vulnerableCertTemplates.length }}}}</dd>
                                        <dd class="text-xs text-gray-500 dark:text-gray-400 mt-1">
                                            ADCS templates
                                        </dd>
                                    </dl>
                                </div>
                            </div>
                        </div>
                        <div v-if="kerberoastable.length > 0" @click="navigateToSection('findings', 'kerberoastable-section')" class="stat-card bg-white dark:bg-gray-800 rounded-lg shadow p-6 cursor-pointer hover:shadow-lg transition-shadow">
                        <div class="flex items-center">
                            <div class="flex-shrink-0 bg-purple-100 dark:bg-purple-900/30 rounded-md p-3">
                                <i class="fas fa-ticket text-purple-600 text-2xl"></i>
                            </div>
                            <div class="ml-5 w-0 flex-1">
                                <dl>
                                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Kerberoastable</dt>
                                    <dd class="text-3xl font-semibold text-gray-900 dark:text-white">{{{{ kerberoastable.length }}}}</dd>
                                    <dd class="text-xs text-gray-500 dark:text-gray-400 mt-1">
                                        Users with SPN
                                    </dd>
                                </dl>
                            </div>
                        </div>
                    </div>
                    
                        <div v-if="asreproastable.length > 0" @click="navigateToSection('findings', 'asreproastable-section')" class="stat-card bg-white dark:bg-gray-800 rounded-lg shadow p-6 cursor-pointer hover:shadow-lg transition-shadow">
                        <div class="flex items-center">
                            <div class="flex-shrink-0 bg-pink-100 dark:bg-pink-900/30 rounded-md p-3">
                                <i class="fas fa-key text-pink-600 text-2xl"></i>
                            </div>
                            <div class="ml-5 w-0 flex-1">
                                <dl>
                                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">ASREPRoastable</dt>
                                    <dd class="text-3xl font-semibold text-gray-900 dark:text-white">{{{{ asreproastable.length }}}}</dd>
                                    <dd class="text-xs text-gray-500 dark:text-gray-400 mt-1">
                                        Users without pre-auth
                                    </dd>
                                </dl>
                            </div>
                        </div>
                    </div>
                    
                        <div v-if="usersWithPasswordsInInfo.length > 0" @click="navigateToSection('findings', 'passwords-section')" class="stat-card bg-white dark:bg-gray-800 rounded-lg shadow p-6 cursor-pointer hover:shadow-lg transition-shadow">
                        <div class="flex items-center">
                            <div class="flex-shrink-0 bg-red-100 dark:bg-red-900/30 rounded-md p-3">
                                <i class="fas fa-lock-open text-red-600 text-2xl"></i>
                            </div>
                            <div class="ml-5 w-0 flex-1">
                                <dl>
                                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Cleartext Passwords</dt>
                                    <dd class="text-3xl font-semibold text-gray-900 dark:text-white">{{{{ usersWithPasswordsInInfo.length }}}}</dd>
                                    <dd class="text-xs text-gray-500 dark:text-gray-400 mt-1">
                                        Found in LDAP attributes
                                    </dd>
                                </dl>
                            </div>
                        </div>
                    </div>
                    
                    <div v-if="lapsReadable.length > 0" @click="navigateToSection('findings', 'laps-section')" class="stat-card bg-white dark:bg-gray-800 rounded-lg shadow p-6 cursor-pointer hover:shadow-lg transition-shadow">
                        <div class="flex items-center">
                            <div class="flex-shrink-0 bg-indigo-100 dark:bg-indigo-900/30 rounded-md p-3">
                                <i class="fas fa-user-shield text-indigo-600 text-2xl"></i>
                            </div>
                            <div class="ml-5 w-0 flex-1">
                                <dl>
                                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">LAPS Readable</dt>
                                    <dd class="text-3xl font-semibold text-gray-900 dark:text-white">{{{{ lapsReadable.length }}}}</dd>
                                    <dd class="text-xs text-gray-500 dark:text-gray-400 mt-1">
                                        Local admin passwords
                                    </dd>
                                </dl>
                            </div>
                        </div>
                    </div>

                    <div v-if="failedCISControls > 0" @click="navigateToSection('findings', 'password-policy-section')" class="stat-card bg-white dark:bg-gray-800 rounded-lg shadow p-6 cursor-pointer hover:shadow-lg transition-shadow">
                        <div class="flex items-center">
                            <div class="flex-shrink-0 bg-yellow-100 dark:bg-yellow-900/30 rounded-md p-3">
                                <i class="fas fa-key text-yellow-600 text-2xl"></i>
                            </div>
                            <div class="ml-5 w-0 flex-1">
                                <dl>
                                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Password Policy</dt>
                                    <dd class="text-3xl font-semibold text-gray-900 dark:text-white">{{{{ failedCISControls }}}}</dd>
                                    <dd class="text-xs text-gray-500 dark:text-gray-400 mt-1">
                                        Failed CIS controls
                                    </dd>
                                </dl>
                            </div>
                        </div>
                    </div>
                    
                    <div v-if="krbtgtOldPassword.length > 0" @click="navigateToSection('findings', 'krbtgt-section')" class="stat-card bg-white dark:bg-gray-800 rounded-lg shadow p-6 cursor-pointer hover:shadow-lg transition-shadow">
                        <div class="flex items-center">
                            <div class="flex-shrink-0 bg-red-100 dark:bg-red-900/30 rounded-md p-3">
                                <i class="fas fa-crown text-red-600 text-2xl"></i>
                            </div>
                            <div class="ml-5 w-0 flex-1">
                                <dl>
                                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">KRBTGT Password Age</dt>
                                    <dd class="text-3xl font-semibold text-gray-900 dark:text-white">{{{{ krbtgtOldPassword.length }}}}</dd>
                                    <dd class="text-xs text-gray-500 dark:text-gray-400 mt-1">
                                        Golden Ticket risk
                                    </dd>
                                </dl>
                            </div>
                        </div>
                    </div>
                    
                    <div v-if="unprotectedPrivilegedUsers.length > 0" @click="navigateToSection('findings', 'protected-users-section')" class="stat-card bg-white dark:bg-gray-800 rounded-lg shadow p-6 cursor-pointer hover:shadow-lg transition-shadow">
                        <div class="flex items-center">
                            <div class="flex-shrink-0 bg-teal-100 dark:bg-teal-900/30 rounded-md p-3">
                                <i class="fas fa-shield-alt text-teal-600 text-2xl"></i>
                            </div>
                            <div class="ml-5 w-0 flex-1">
                                <dl>
                                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Privileged Users</dt>
                                    <dd class="text-3xl font-semibold text-gray-900 dark:text-white">{{{{ unprotectedPrivilegedUsers.length }}}}</dd>
                                    <dd class="text-xs text-gray-500 dark:text-gray-400 mt-1">
                                        Not in Protected Users
                                    </dd>
                                </dl>
                            </div>
                        </div>
                    </div>
                    
                    <div v-if="machineAccountQuota > 0" @click="navigateToSection('findings', 'machine-quota-section')" class="stat-card bg-white dark:bg-gray-800 rounded-lg shadow p-6 cursor-pointer hover:shadow-lg transition-shadow">
                        <div class="flex items-center">
                            <div class="flex-shrink-0 bg-amber-100 dark:bg-amber-900/30 rounded-md p-3">
                                <i class="fas fa-server text-amber-600 text-2xl"></i>
                            </div>
                            <div class="ml-5 w-0 flex-1">
                                <dl>
                                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Machine Account Quota</dt>
                                    <dd class="text-3xl font-semibold text-gray-900 dark:text-white">{{{{ machineAccountQuota }}}}</dd>
                                    <dd class="text-xs text-gray-500 dark:text-gray-400 mt-1">
                                        computers can be added
                                    </dd>
                                </dl>
                            </div>
                        </div>
                    </div>
                </div>
                </div>

                <!-- Domain Information Tiles -->
                <div class="mb-6">
                    <h3 class="text-lg font-semibold text-gray-700 dark:text-gray-300 mb-3">
                        <i class="fas fa-info-circle"></i> Domain Information
                    </h3>
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">

                    <div class="stat-card bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                        <div class="flex items-center">
                            <div class="flex-shrink-0 bg-cyan-100 dark:bg-cyan-900/30 rounded-md p-3">
                                <i class="fas fa-server text-cyan-600 text-2xl"></i>
                            </div>
                            <div class="ml-5 w-0 flex-1">
                                <dl>
                                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Domain Controllers</dt>
                                    <dd class="text-3xl font-semibold text-gray-900 dark:text-white">{{{{ domainControllers.length }}}}</dd>
                                    <dd class="text-xs text-gray-500 dark:text-gray-400 mt-1">More details in XLSX</dd>
                                </dl>
                            </div>
                        </div>
                    </div>

                        <div @click="activeTab = 'users'; userFilter = 'all'; activeView = 'all';" class="stat-card bg-white dark:bg-gray-800 rounded-lg shadow p-6 cursor-pointer hover:shadow-lg transition-shadow">
                        <div class="flex items-center">
                            <div class="flex-shrink-0 bg-blue-100 dark:bg-blue-900/30 rounded-md p-3">
                                <i class="fas fa-users text-blue-600 text-2xl"></i>
                            </div>
                            <div class="ml-5 w-0 flex-1">
                                <dl>
                                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">
                                        Total Users
                                    </dt>
                                    <dd class="text-3xl font-semibold text-gray-900 dark:text-white">
                                        {{{{ users.length }}}}
                                    </dd>
                                    <dd class="text-sm text-gray-500 dark:text-gray-400">
                                        {{{{ enabledUsers.length }}}} enabled
                                    </dd>
                                </dl>
                            </div>
                        </div>
                    </div>

                        <div @click="activeTab = 'users'; userFilter = 'privileged';" class="stat-card bg-white dark:bg-gray-800 rounded-lg shadow p-6 cursor-pointer hover:shadow-lg transition-shadow">
                        <div class="flex items-center">
                            <div class="flex-shrink-0 bg-yellow-100 dark:bg-yellow-900/30 rounded-md p-3">
                                <i class="fas fa-user-shield text-yellow-600 text-2xl"></i>
                            </div>
                            <div class="ml-5 w-0 flex-1">
                                <dl>
                                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">
                                        Privileged Users
                                    </dt>
                                    <dd class="text-3xl font-semibold text-gray-900 dark:text-white">
                                        {{{{ privilegedUsers.length }}}}
                                    </dd>
                                    <dd class="text-xs text-gray-500 dark:text-gray-400 mt-1">
                                        AdminCount=1
                                    </dd>
                                </dl>
                            </div>
                        </div>
                    </div>

                    <div @click="activeTab = 'users'; userFilter = 'dormant';" class="stat-card bg-white dark:bg-gray-800 rounded-lg shadow p-6 cursor-pointer hover:shadow-lg transition-shadow">
                        <div class="flex items-center">
                            <div class="flex-shrink-0 bg-gray-100 dark:bg-gray-700 rounded-md p-3">
                                <i class="fas fa-user-clock text-gray-600 text-2xl"></i>
                            </div>
                            <div class="ml-5 w-0 flex-1">
                                <dl>
                                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Dormant Users</dt>
                                    <dd class="text-3xl font-semibold text-gray-900 dark:text-white">{{{{ dormantUsers.length }}}}</dd>
                                    <dd class="text-xs text-gray-500 dark:text-gray-400">90+ days inactive</dd>
                                </dl>
                            </div>
                        </div>
                    </div>

                    <div class="stat-card bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                        <div class="flex items-center">
                            <div class="flex-shrink-0 bg-teal-100 dark:bg-teal-900/30 rounded-md p-3">
                                <i class="fas fa-cog text-teal-600 text-2xl"></i>
                            </div>
                            <div class="ml-5 w-0 flex-1">
                                <dl>
                                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">gMSA</dt>
                                    <dd class="text-3xl font-semibold text-gray-900 dark:text-white">{{{{ gmsa.length }}}}</dd>
                                    <dd class="text-xs text-gray-500 dark:text-gray-400 mt-1">More details in XLSX</dd>
                                </dl>
                            </div>
                        </div>
                    </div>

                        <div @click="activeTab = 'computers'; activeView = 'all';" class="stat-card bg-white dark:bg-gray-800 rounded-lg shadow p-6 cursor-pointer hover:shadow-lg transition-shadow">
                        <div class="flex items-center">
                            <div class="flex-shrink-0 bg-green-100 dark:bg-green-900/30 rounded-md p-3">
                                <i class="fas fa-desktop text-green-600 text-2xl"></i>
                            </div>
                            <div class="ml-5 w-0 flex-1">
                                <dl>
                                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">
                                        Computers
                                    </dt>
                                    <dd class="text-3xl font-semibold text-gray-900 dark:text-white">
                                        {{{{ computers.length }}}}
                                    </dd>
                                    <dd class="text-sm text-gray-500 dark:text-gray-400">
                                        {{{{ enabledComputers.length }}}} enabled
                                    </dd>
                                </dl>
                            </div>
                        </div>
                    </div>

                    <div class="stat-card bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                        <div class="flex items-center">
                            <div class="flex-shrink-0 bg-amber-100 dark:bg-amber-900/30 rounded-md p-3">
                                <i class="fas fa-print text-amber-600 text-2xl"></i>
                            </div>
                            <div class="ml-5 w-0 flex-1">
                                <dl>
                                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Printers</dt>
                                    <dd class="text-3xl font-semibold text-gray-900 dark:text-white">{{{{ printers.length }}}}</dd>
                                    <dd class="text-xs text-gray-500 dark:text-gray-400 mt-1">More details in XLSX</dd>
                                </dl>
                            </div>
                        </div>
                    </div>

                    <div class="stat-card bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                        <div class="flex items-center">
                            <div class="flex-shrink-0 bg-purple-100 dark:bg-purple-900/30 rounded-md p-3">
                                <i class="fas fa-users-cog text-purple-600 text-2xl"></i>
                            </div>
                            <div class="ml-5 w-0 flex-1">
                                <dl>
                                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Groups</dt>
                                    <dd class="text-3xl font-semibold text-gray-900 dark:text-white">{{{{ groups.length }}}}</dd>
                                    <dd class="text-xs text-gray-500 dark:text-gray-400 mt-1">More details in XLSX</dd>
                                </dl>
                            </div>
                        </div>
                    </div>

                    <div class="stat-card bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                        <div class="flex items-center">
                            <div class="flex-shrink-0 bg-rose-100 dark:bg-rose-900/30 rounded-md p-3">
                                <i class="fas fa-list-check text-rose-600 text-2xl"></i>
                            </div>
                            <div class="ml-5 w-0 flex-1">
                                <dl>
                                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">GPOs</dt>
                                    <dd class="text-3xl font-semibold text-gray-900 dark:text-white">{{{{ gpos.length }}}}</dd>
                                    <dd class="text-xs text-gray-500 dark:text-gray-400 mt-1">More details in XLSX</dd>
                                </dl>
                            </div>
                        </div>
                    </div>

                    <div class="stat-card bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                        <div class="flex items-center">
                            <div class="flex-shrink-0 bg-emerald-100 dark:bg-emerald-900/30 rounded-md p-3">
                                <i class="fas fa-certificate text-emerald-600 text-2xl"></i>
                            </div>
                            <div class="ml-5 w-0 flex-1">
                                <dl>
                                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Certificate Authorities</dt>
                                    <dd class="text-3xl font-semibold text-gray-900 dark:text-white">{{{{ certificateAuthorities.length }}}}</dd>
                                    <dd class="text-xs text-gray-500 dark:text-gray-400 mt-1">More details in XLSX</dd>
                                </dl>
                            </div>
                        </div>
                    </div>

                    <div class="stat-card bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                        <div class="flex items-center">
                            <div class="flex-shrink-0 bg-lime-100 dark:bg-lime-900/30 rounded-md p-3">
                                <i class="fas fa-sitemap text-lime-600 text-2xl"></i>
                            </div>
                            <div class="ml-5 w-0 flex-1">
                                <dl>
                                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Trusts</dt>
                                    <dd class="text-3xl font-semibold text-gray-900 dark:text-white">{{{{ trusts.length }}}}</dd>
                                    <dd class="text-xs text-gray-500 dark:text-gray-400 mt-1">More details in XLSX</dd>
                                </dl>
                            </div>
                        </div>
                    </div>

                    <div class="stat-card bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                        <div class="flex items-center">
                            <div class="flex-shrink-0 bg-indigo-100 dark:bg-indigo-900/30 rounded-md p-3">
                                <i class="fas fa-folder-tree text-indigo-600 text-2xl"></i>
                            </div>
                            <div class="ml-5 w-0 flex-1">
                                <dl>
                                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">OUs</dt>
                                    <dd class="text-3xl font-semibold text-gray-900 dark:text-white">{{{{ ous.length }}}}</dd>
                                    <dd class="text-xs text-gray-500 dark:text-gray-400 mt-1">More details in XLSX</dd>
                                </dl>
                            </div>
                        </div>
                    </div>

                    <div class="stat-card bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                        <div class="flex items-center">
                            <div class="flex-shrink-0 bg-sky-100 dark:bg-sky-900/30 rounded-md p-3">
                                <i class="fas fa-map-marked-alt text-sky-600 text-2xl"></i>
                            </div>
                            <div class="ml-5 w-0 flex-1">
                                <dl>
                                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Sites</dt>
                                    <dd class="text-3xl font-semibold text-gray-900 dark:text-white">{{{{ sites.length }}}}</dd>
                                    <dd class="text-xs text-gray-500 dark:text-gray-400 mt-1">More details in XLSX</dd>
                                </dl>
                            </div>
                        </div>
                    </div>

                    <div class="stat-card bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                        <div class="flex items-center">
                            <div class="flex-shrink-0 bg-violet-100 dark:bg-violet-900/30 rounded-md p-3">
                                <i class="fas fa-network-wired text-violet-600 text-2xl"></i>
                            </div>
                            <div class="ml-5 w-0 flex-1">
                                <dl>
                                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Subnets</dt>
                                    <dd class="text-3xl font-semibold text-gray-900 dark:text-white">{{{{ subnets.length }}}}</dd>
                                    <dd class="text-xs text-gray-500 dark:text-gray-400 mt-1">More details in XLSX</dd>
                                </dl>
                            </div>
                        </div>
                    </div>

                    <div class="stat-card bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                        <div class="flex items-center">
                            <div class="flex-shrink-0 bg-fuchsia-100 dark:bg-fuchsia-900/30 rounded-md p-3">
                                <i class="fas fa-shield-halved text-fuchsia-600 text-2xl"></i>
                            </div>
                            <div class="ml-5 w-0 flex-1">
                                <dl>
                                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Fine-Grained Pwd Policies</dt>
                                    <dd class="text-3xl font-semibold text-gray-900 dark:text-white">{{{{ fineGrainedPasswordPolicy.length }}}}</dd>
                                    <dd class="text-xs text-gray-500 dark:text-gray-400 mt-1">More details in XLSX</dd>
                                </dl>
                            </div>
                        </div>
                    </div>
                </div>
                </div>

                <!-- User Account Status Chart -->
                <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                    <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                        <i class="fas fa-chart-bar"></i> User Account Status Overview
                    </h3>
                    <canvas id="userStatusChart"></canvas>
                </div>

                <!-- Domain Trust Graph -->
                <div v-if="trusts.length > 0" class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                    <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                        <i class="fas fa-sitemap"></i> Domain Trust Relationships
                    </h3>
                    <div id="trustGraph"></div>
                    <div class="mt-4 flex items-center flex-wrap gap-4 text-sm text-gray-600 dark:text-gray-400">
                        <div class="flex items-center">
                            <div class="w-4 h-4 bg-blue-500 rounded mr-2"></div>
                            <span>Source Domain</span>
                        </div>
                        <div class="flex items-center">
                            <div class="w-4 h-4 bg-green-500 rounded mr-2"></div>
                            <span>Trusted Domain</span>
                        </div>
                        <div class="flex items-center">
                            <div class="w-4 h-4 bg-purple-500 rounded-full mr-2"></div>
                            <span>User Counts</span>
                        </div>
                        <div class="flex items-center">
                            <div class="w-4 h-4 bg-amber-500 rounded-full mr-2"></div>
                            <span>Computer Counts</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Findings Tab -->
            <div v-if="activeTab === 'findings'" class="space-y-6">
                <!-- ESC Vulnerable ADCS Templates -->
                <div id="adcs-templates-section" v-if="vulnerableCertTemplates.length > 0" class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                    <h2 class="text-2xl font-bold text-gray-900 dark:text-white mb-4">
                        <i class="fas fa-certificate text-orange-600"></i> ESC Vulnerable ADCS Templates ({{{{ vulnerableCertTemplates.length }}}})
                    </h2>
                    <div class="bg-orange-50 dark:bg-orange-900/20 border-l-4 border-orange-500 p-4 mb-6">
                        <h3 class="font-semibold text-orange-800 dark:text-orange-200 mb-2">🎯 Issue & Impact</h3>
                        <p class="text-orange-700 dark:text-orange-300 text-sm mb-3">
                            Active Directory Certificate Services (ADCS) templates vulnerable to privilege escalation techniques cataloged as ESC (Escalation Scenarios). Misconfigured templates allow unauthorized certificate enrollment, leading to authentication as privileged users.
                        </p>
                        <h3 class="font-semibold text-orange-800 dark:text-orange-200 mb-2">⚔️ Attacker Benefit</h3>
                        <p class="text-orange-700 dark:text-orange-300 text-sm mb-3">
                            Attackers can request rogue certificates for domain administrators or other high-privilege accounts, achieving persistent domain compromise without account credentials.
                        </p>
                        <h3 class="font-semibold text-orange-800 dark:text-orange-200 mb-2">🔓 Exploitation Method</h3>
                        <p class="text-orange-700 dark:text-orange-300 text-sm mb-3">
                            Tools like <a href="https://github.com/ly4k/Certipy" target="_blank" class="tool-link">Certipy</a> or <a href="https://github.com/GhostPack/Certify" target="_blank" class="tool-link">Certify</a> identify vulnerable templates. Attackers request certificates with elevated permissions, then authenticate using the certificate to obtain TGTs or NTLM hashes.
                        </p>
                        <h3 class="font-semibold text-orange-800 dark:text-orange-200 mb-2">💡 Remediation</h3>
                        <p class="text-orange-700 dark:text-orange-300 text-sm">
                            <strong>Secure template permissions:</strong> Remove enrollment rights from Domain Users/Authenticated Users. Enable Manager Approval for high-risk templates. Set "This number of authorized signatures" to ≥1 for ESC1. Disable "Enrollee Supplies Subject" or require manager approval. Regularly audit certificate templates against ESC vulnerabilities using <a href="https://github.com/GhostPack/Certify" target="_blank" class="tool-link">Certify</a>, <a href="https://github.com/ly4k/Certipy" target="_blank" class="tool-link">Certipy</a> or <a href="https://github.com/TrimarcJake/Locksmith" target="_blank" class="tool-link">Locksmith</a>.
                        </p>
                    </div>
                    <div class="table-container">
                        <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                            <thead>
                                <tr>
                                    <th @click="sortVulnCertTemplates('Template Name')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        Template Name
                                        <i v-if="vulnCertTemplateSortColumn === 'Template Name'" :class="vulnCertTemplateSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th @click="sortVulnCertTemplates('ESC Vulnerabilities')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        ESC Vulnerabilities
                                        <i v-if="vulnCertTemplateSortColumn === 'ESC Vulnerabilities'" :class="vulnCertTemplateSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th @click="sortVulnCertTemplates('Risk Factors')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        Risk Factors
                                        <i v-if="vulnCertTemplateSortColumn === 'Risk Factors'" :class="vulnCertTemplateSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th @click="sortVulnCertTemplates('Enrollment Rights')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        Enrollment Rights
                                        <i v-if="vulnCertTemplateSortColumn === 'Enrollment Rights'" :class="vulnCertTemplateSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th @click="sortVulnCertTemplates('Risk Level')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        Risk Level
                                        <i v-if="vulnCertTemplateSortColumn === 'Risk Level'" :class="vulnCertTemplateSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
                                <tr v-for="template in vulnerableCertTemplates" :key="template['Template Name']">
                                    <td class="px-6 py-4 whitespace-nowrap font-medium">{{{{ template['Template Name'] }}}}</td>
                                    <td class="px-6 py-4">
                                        <span v-if="template['ESC Vulnerabilities'] !== 'None'" class="text-red-600 dark:text-red-400 font-semibold">
                                            {{{{ template['ESC Vulnerabilities'] }}}}
                                        </span>
                                        <span v-else class="text-gray-500">None</span>
                                    </td>
                                    <td class="px-6 py-4 text-sm">{{{{ template['Risk Factors'] !== 'None' ? template['Risk Factors'] : '-' }}}}</td>
                                    <td class="px-6 py-4 text-sm">{{{{ template['Enrollment Rights'] }}}}</td>
                                    <td class="px-6 py-4">
                                        <span v-if="template['Risk Level'] === 'CRITICAL'" class="badge badge-critical">CRITICAL</span>
                                        <span v-else-if="template['Risk Level'] === 'HIGH'" class="badge badge-high">HIGH</span>
                                        <span v-else-if="template['Risk Level'] && (template['Risk Level'] === 'MEDIUM' || template['Risk Level'] === 'Medium')" class="badge badge-medium">MEDIUM</span>
                                        <span v-else-if="template['Risk Level'] && (template['Risk Level'] === 'LOW' || template['Risk Level'] === 'Low')" class="badge badge-low">LOW</span>
                                        <span v-else class="badge badge-none">None</span>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Kerberoastable Accounts -->
                <div id="kerberoastable-section" v-if="kerberoastable.length > 0" class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                    <h2 class="text-2xl font-bold text-gray-900 dark:text-white mb-4">
                        <i class="fas fa-ticket text-purple-600"></i> Kerberoastable Accounts ({{{{ kerberoastable.length }}}})
                    </h2>
                    <div class="bg-purple-50 dark:bg-purple-900/20 border-l-4 border-purple-500 p-4 mb-6">
                        <h3 class="font-semibold text-purple-800 dark:text-purple-200 mb-2">🎯 Issue & Impact</h3>
                        <p class="text-purple-700 dark:text-purple-300 text-sm mb-3">
                            Service accounts with registered SPNs (Service Principal Names) are vulnerable to Kerberoasting. The TGS (Ticket Granting Service) ticket contains the service account's password hash encrypted with that account's password.
                        </p>
                        <h3 class="font-semibold text-purple-800 dark:text-purple-200 mb-2">⚔️ Attacker Benefit</h3>
                        <p class="text-purple-700 dark:text-purple-300 text-sm mb-3">
                            Any domain user can request TGS tickets for these accounts and perform offline password cracking without raising alerts. Weak or old passwords are particularly vulnerable.
                        </p>
                        <h3 class="font-semibold text-purple-800 dark:text-purple-200 mb-2">🔓 Exploitation Method</h3>
                        <p class="text-purple-700 dark:text-purple-300 text-sm mb-3">
                            Tools: Rubeus, Invoke-Kerberoast, GetUserSPNs.py. Request TGS tickets, extract to disk, crack with Hashcat/John. Success = service account compromise.
                        </p>
                        <h3 class="font-semibold text-purple-800 dark:text-purple-200 mb-2">💡 Remediation</h3>
                        <p class="text-purple-700 dark:text-purple-300 text-sm">
                            <strong>Use strong passwords (25+ characters) or better gMSA:</strong> Service accounts should use Group Managed Service Accounts (gMSA) which auto-rotate passwords. For standard accounts, enforce minimum 25-character passwords, rotate every 90 days, and implement least privilege. Remove unnecessary SPNs from user accounts.
                        </p>
                    </div>
                    <div class="table-container">
                        <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                            <thead>
                                <tr>
                                    <th @click="sortKerberoast('SAM Account Name')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        User
                                        <i v-if="kerberoastSortColumn === 'SAM Account Name'" :class="kerberoastSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th @click="sortKerberoast('Service Principal Names')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        SPN
                                        <i v-if="kerberoastSortColumn === 'Service Principal Names'" :class="kerberoastSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th @click="sortKerberoast('Password Age (days)')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        Password Age
                                        <i v-if="kerberoastSortColumn === 'Password Age (days)'" :class="kerberoastSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th @click="sortKerberoast('AdminCount')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        Admin
                                        <i v-if="kerberoastSortColumn === 'AdminCount'" :class="kerberoastSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
                                <tr v-for="user in paginatedKerberoast" :key="user['SAM Account Name']">
                                    <td class="px-6 py-4 whitespace-nowrap font-medium">{{{{ user['SAM Account Name'] }}}}</td>
                                    <td class="px-6 py-4 text-sm">{{{{ user['Service Principal Names'] }}}}</td>
                                    <td class="px-6 py-4">
                                        <span :class="parseInt(user['Password Age (days)']) > 365 ? 'badge badge-high' : parseInt(user['Password Age (days)']) > 180 ? 'badge badge-medium' : 'badge badge-low'">
                                            {{{{ user['Password Age (days)'] }}}} days
                                        </span>
                                    </td>
                                    <td class="px-6 py-4">
                                        <span v-if="user.AdminCount === '1'" class="badge badge-critical">Admin</span>
                                        <span v-else class="badge badge-none">-</span>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                    <div v-if="kerberoastable.length > itemsPerPage" class="flex justify-between items-center py-4">
                        <div class="text-sm text-gray-500 dark:text-gray-400">
                            Showing {{{{ ((kerberoastPage - 1) * itemsPerPage) + 1 }}}} to {{{{ Math.min(kerberoastPage * itemsPerPage, kerberoastable.length) }}}} of {{{{ kerberoastable.length }}}} accounts
                        </div>
                        <div class="flex gap-2">
                            <button @click="kerberoastPage = Math.max(1, kerberoastPage - 1)" :disabled="kerberoastPage === 1" 
                                    class="px-3 py-1 rounded bg-blue-600 text-white disabled:bg-gray-400">
                                <i class="fas fa-chevron-left"></i> Previous
                            </button>
                            <span class="px-3 py-1">Page {{{{ kerberoastPage }}}} of {{{{ Math.ceil(kerberoastable.length / itemsPerPage) }}}}</span>
                            <button @click="kerberoastPage = Math.min(Math.ceil(kerberoastable.length / itemsPerPage), kerberoastPage + 1)" 
                                    :disabled="kerberoastPage >= Math.ceil(kerberoastable.length / itemsPerPage)"
                                    class="px-3 py-1 rounded bg-blue-600 text-white disabled:bg-gray-400">
                                Next <i class="fas fa-chevron-right"></i>
                            </button>
                        </div>
                    </div>
                </div>

                <!-- ASREPRoastable Accounts -->
                <div id="asreproastable-section" v-if="asreproastable.length > 0" class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                    <h2 class="text-2xl font-bold text-gray-900 dark:text-white mb-4">
                        <i class="fas fa-key text-pink-600"></i> ASREPRoastable Accounts ({{{{ asreproastable.length }}}})
                    </h2>
                    <div class="bg-pink-50 dark:bg-pink-900/20 border-l-4 border-pink-500 p-4 mb-6">
                        <h3 class="font-semibold text-pink-800 dark:text-pink-200 mb-2">🎯 Issue & Impact</h3>
                        <p class="text-pink-700 dark:text-pink-300 text-sm mb-3">
                            Accounts with "Do not require Kerberos preauthentication" enabled bypass the authentication step that normally prevents offline attacks. The AS-REP response contains encrypted material based on the user's password.
                        </p>
                        <h3 class="font-semibold text-pink-800 dark:text-pink-200 mb-2">⚔️ Attacker Benefit</h3>
                        <p class="text-pink-700 dark:text-pink-300 text-sm mb-3">
                            No authentication required - attackers can request AS-REP messages for these accounts without valid credentials and perform offline brute-force attacks.
                        </p>
                        <h3 class="font-semibold text-pink-800 dark:text-pink-200 mb-2">🔓 Exploitation Method</h3>
                        <p class="text-pink-700 dark:text-pink-300 text-sm mb-3">
                            Tools: Rubeus, GetNPUsers.py. Request AS-REP for target accounts, extract encrypted portion, crack offline with Hashcat format 18200 or John.
                        </p>
                        <h3 class="font-semibold text-pink-800 dark:text-pink-200 mb-2">💡 Remediation</h3>
                        <p class="text-pink-700 dark:text-pink-300 text-sm">
                            <strong>Enable Kerberos pre-authentication:</strong> Remove "Do not require Kerberos preauthentication" flag from all user accounts unless absolutely necessary for legacy applications. For required exceptions, enforce strong passwords (25+ characters), monitor for AS-REP requests, and consider isolating these accounts to restricted network segments.
                        </p>
                    </div>
                    <div class="table-container">
                        <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                            <thead>
                                <tr>
                                    <th @click="sortAsrep('SAM Account Name')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        User
                                        <i v-if="asrepSortColumn === 'SAM Account Name'" :class="asrepSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th @click="sortAsrep('Description')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        Description
                                        <i v-if="asrepSortColumn === 'Description'" :class="asrepSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th @click="sortAsrep('Password Age (days)')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        Password Age
                                        <i v-if="asrepSortColumn === 'Password Age (days)'" :class="asrepSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th @click="sortAsrep('AdminCount')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        Admin
                                        <i v-if="asrepSortColumn === 'AdminCount'" :class="asrepSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
                                <tr v-for="user in paginatedAsrep" :key="user['SAM Account Name']">
                                    <td class="px-6 py-4 whitespace-nowrap font-medium">{{{{ user['SAM Account Name'] }}}}</td>
                                    <td class="px-6 py-4 text-sm">{{{{ user.Description }}}}</td>
                                    <td class="px-6 py-4">
                                        <span :class="parseInt(user['Password Age (days)']) > 365 ? 'badge badge-high' : parseInt(user['Password Age (days)']) > 180 ? 'badge badge-medium' : 'badge badge-low'">
                                            {{{{ user['Password Age (days)'] }}}} days
                                        </span>
                                    </td>
                                    <td class="px-6 py-4">
                                        <span v-if="user.AdminCount === '1'" class="badge badge-critical">Admin</span>
                                        <span v-else class="badge badge-none">-</span>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                    <div v-if="asreproastable.length > itemsPerPage" class="flex justify-between items-center py-4">
                        <div class="text-sm text-gray-500 dark:text-gray-400">
                            Showing {{{{ ((asrepPage - 1) * itemsPerPage) + 1 }}}} to {{{{ Math.min(asrepPage * itemsPerPage, asreproastable.length) }}}} of {{{{ asreproastable.length }}}} accounts
                        </div>
                        <div class="flex gap-2">
                            <button @click="asrepPage = Math.max(1, asrepPage - 1)" :disabled="asrepPage === 1" 
                                    class="px-3 py-1 rounded bg-blue-600 text-white disabled:bg-gray-400">
                                <i class="fas fa-chevron-left"></i> Previous
                            </button>
                            <span class="px-3 py-1">Page {{{{ asrepPage }}}} of {{{{ Math.ceil(asreproastable.length / itemsPerPage) }}}}</span>
                            <button @click="asrepPage = Math.min(Math.ceil(asreproastable.length / itemsPerPage), asrepPage + 1)" 
                                    :disabled="asrepPage >= Math.ceil(asreproastable.length / itemsPerPage)"
                                    class="px-3 py-1 rounded bg-blue-600 text-white disabled:bg-gray-400">
                                Next <i class="fas fa-chevron-right"></i>
                            </button>
                        </div>
                    </div>
                </div>

                <!-- Cleartext Passwords in User Fields -->
                <div id="passwords-section" v-if="usersWithPasswordsInInfo.length > 0" class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                    <h2 class="text-2xl font-bold text-gray-900 dark:text-white mb-4">
                        <i class="fas fa-lock-open text-red-600"></i> Cleartext Passwords in User Fields ({{{{ usersWithPasswordsInInfo.length }}}})
                    </h2>
                    <div class="bg-red-50 dark:bg-red-900/20 border-l-4 border-red-500 p-4 mb-6">
                        <h3 class="font-semibold text-red-800 dark:text-red-200 mb-2">🎯 Issue & Impact</h3>
                        <p class="text-red-700 dark:text-red-300 text-sm mb-3">
                            User accounts with cleartext or easily identifiable passwords stored in Description or Info fields. This represents severe security hygiene failure where credentials are exposed to any authenticated user.
                        </p>
                        <h3 class="font-semibold text-red-800 dark:text-red-200 mb-2">⚔️ Attacker Benefit</h3>
                        <p class="text-red-700 dark:text-red-300 text-sm mb-3">
                            Instant account compromise without cracking. Attackers simply read user attributes to obtain valid credentials, enabling lateral movement and privilege escalation.
                        </p>
                        <h3 class="font-semibold text-red-800 dark:text-red-200 mb-2">🔓 Exploitation Method</h3>
                        <p class="text-red-700 dark:text-red-300 text-sm mb-3">
                            LDAP queries or tools like BloodHound/PowerView enumerate user descriptions containing password patterns. Direct login with discovered credentials.
                        </p>
                        <h3 class="font-semibold text-red-800 dark:text-red-200 mb-2">💡 Remediation</h3>
                        <p class="text-red-700 dark:text-red-300 text-sm">
                            <strong>Immediately remove all passwords from user attributes:</strong> Clear 'description' and 'info' fields of all password-like strings. Never store secrets in LDAP attributes again. Force password resets for affected accounts. Implement security awareness training about proper credential storage. Regularly audit user attributes using scripts to detect and prevent future occurrences.
                        </p>
                    </div>
                    <div class="table-container">
                        <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                            <thead>
                                <tr>
                                    <th @click="sortCleartext('UserName')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        Username
                                        <i v-if="cleartextSortColumn === 'UserName'" :class="cleartextSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th @click="sortCleartext('Name')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        Name
                                        <i v-if="cleartextSortColumn === 'Name'" :class="cleartextSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th @click="sortCleartext('Description')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        Description
                                        <i v-if="cleartextSortColumn === 'Description'" :class="cleartextSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th @click="sortCleartext('Info')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        Info
                                        <i v-if="cleartextSortColumn === 'Info'" :class="cleartextSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th @click="sortCleartext('AdminCount')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        Admin
                                        <i v-if="cleartextSortColumn === 'AdminCount'" :class="cleartextSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
                                <tr v-for="user in usersWithPasswordsInInfo.slice(0, 50)" :key="user.UserName">
                                    <td class="px-6 py-4 whitespace-nowrap font-medium">{{{{ user.UserName }}}}</td>
                                    <td class="px-6 py-4">{{{{ user.Name }}}}</td>
                                    <td class="px-6 py-4 text-sm">
                                        <span v-if="user.Description" class="text-red-600 dark:text-red-400 font-mono break-all">{{{{ user.Description }}}}</span>
                                        <span v-else class="text-gray-400">-</span>
                                    </td>
                                    <td class="px-6 py-4 text-sm">
                                        <span v-if="user.Info" class="text-red-600 dark:text-red-400 font-mono break-all">{{{{ user.Info }}}}</span>
                                        <span v-else class="text-gray-400">-</span>
                                    </td>
                                    <td class="px-6 py-4">
                                        <span v-if="user.AdminCount === '1'" class="badge badge-critical">Admin</span>
                                        <span v-else class="text-gray-500">-</span>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- LAPS Readable Passwords -->
                <div id="laps-section" v-if="lapsReadable.length > 0" class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                    <h2 class="text-2xl font-bold text-gray-900 dark:text-white mb-4">
                        <i class="fas fa-key text-indigo-600"></i> LAPS Readable Passwords ({{{{ lapsReadable.length }}}})
                    </h2>
                    <div class="bg-indigo-50 dark:bg-indigo-900/20 border-l-4 border-indigo-500 p-4 mb-6">
                        <h3 class="font-semibold text-indigo-800 dark:text-indigo-200 mb-2">🎯 Issue & Impact</h3>
                        <p class="text-indigo-700 dark:text-indigo-300 text-sm mb-3">
                            Local Administrator Password Solution (LAPS) stores randomized local admin passwords in AD. Misconfigured read permissions allow unauthorized users to retrieve these privileged credentials.
                        </p>
                        <h3 class="font-semibold text-indigo-800 dark:text-indigo-200 mb-2">⚔️ Attacker Benefit</h3>
                        <p class="text-indigo-700 dark:text-indigo-300 text-sm mb-3">
                            Compromised systems with readable LAPS passwords grant local administrator access, enabling credential dumping, persistence mechanisms, and lateral movement across the environment.
                        </p>
                        <h3 class="font-semibold text-indigo-800 dark:text-indigo-200 mb-2">🔓 Exploitation Method</h3>
                        <p class="text-indigo-700 dark:text-indigo-300 text-sm mb-3">
                            Query AD attributes ms-Mcs-AdmPwd and ms-Mcs-AdmPwdExpirationTime. Tools: LAPSToolkit, PowerView. Use retrieved passwords for PSExec/WMI/RDP access.
                        </p>
                        <h3 class="font-semibold text-indigo-800 dark:text-indigo-200 mb-2">💡 Remediation</h3>
                        <p class="text-indigo-700 dark:text-indigo-300 text-sm">
                            <strong>Restrict LAPS password read permissions:</strong> Only designated IT admin groups should have read access to ms-Mcs-AdmPwd attribute. Remove "All Extended Rights" and grant only specific LAPS read permissions to authorized security groups. Regularly audit permissions using AccessChk or custom scripts. Consider implementing LAPS password rotation to limit exposure window.
                        </p>
                    </div>
                    <div class="table-container">
                        <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                            <thead>
                                <tr>
                                    <th @click="sortLaps('Hostname')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        Computer
                                        <i v-if="lapsSortColumn === 'Hostname'" :class="lapsSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th @click="sortLaps('Enabled')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        LAPS Enabled
                                        <i v-if="lapsSortColumn === 'Enabled'" :class="lapsSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th @click="sortLaps('Stored')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        Password Stored
                                        <i v-if="lapsSortColumn === 'Stored'" :class="lapsSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th @click="sortLaps('Readable')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        Readable
                                        <i v-if="lapsSortColumn === 'Readable'" :class="lapsSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th @click="sortLaps('Password')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        Password
                                        <i v-if="lapsSortColumn === 'Password'" :class="lapsSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th @click="sortLaps('Expiration')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        Expiry
                                        <i v-if="lapsSortColumn === 'Expiration'" :class="lapsSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
                                <tr v-for="computer in paginatedLaps" :key="computer.Hostname">
                                    <td class="px-6 py-4 whitespace-nowrap font-medium">{{{{ computer.Hostname || 'N/A' }}}}</td>
                                    <td class="px-6 py-4">
                                        <span v-if="computer.Enabled === 'True'" class="badge badge-low">Yes</span>
                                        <span v-else class="badge badge-none">No</span>
                                    </td>
                                    <td class="px-6 py-4">
                                        <span v-if="computer.Stored === 'True'" class="badge badge-low">Yes</span>
                                        <span v-else class="badge badge-none">No</span>
                                    </td>
                                    <td class="px-6 py-4">
                                        <span v-if="computer.Readable === 'True'" class="badge badge-high">Yes</span>
                                        <span v-else class="badge badge-none">No</span>
                                    </td>
                                    <td class="px-6 py-4 font-mono text-sm">
                                        <span v-if="computer.Password" class="text-red-600 dark:text-red-400 font-semibold">{{{{ computer.Password }}}}</span>
                                        <span v-else class="text-gray-400">-</span>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap">{{{{ computer.Expiration || 'N/A' }}}}</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                    <div v-if="lapsReadable.length > itemsPerPage" class="flex justify-between items-center mt-4">
                        <div class="text-sm text-gray-500 dark:text-gray-400">
                            Showing {{{{ ((lapsPage - 1) * itemsPerPage) + 1 }}}} to {{{{ Math.min(lapsPage * itemsPerPage, lapsReadable.length) }}}} of {{{{ lapsReadable.length }}}} computers
                        </div>
                        <div class="flex gap-2">
                            <button @click="lapsPage = Math.max(1, lapsPage - 1)" :disabled="lapsPage === 1" 
                                    class="px-3 py-1 rounded bg-blue-600 text-white disabled:bg-gray-400">
                                <i class="fas fa-chevron-left"></i> Previous
                            </button>
                            <span class="px-3 py-1">Page {{{{ lapsPage }}}} of {{{{ Math.ceil(lapsReadable.length / itemsPerPage) }}}}</span>
                            <button @click="lapsPage = Math.min(Math.ceil(lapsReadable.length / itemsPerPage), lapsPage + 1)" 
                                    :disabled="lapsPage >= Math.ceil(lapsReadable.length / itemsPerPage)"
                                    class="px-3 py-1 rounded bg-blue-600 text-white disabled:bg-gray-400">
                                Next <i class="fas fa-chevron-right"></i>
                            </button>
                        </div>
                    </div>
                </div>

                <!-- KRBTGT Password Rotation -->
                <div id="krbtgt-section" v-if="krbtgtOldPassword.length > 0" class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                    <h2 class="text-2xl font-bold text-gray-900 dark:text-white mb-4">
                        <i class="fas fa-crown text-red-600"></i> KRBTGT Password Rotation ({{{{ krbtgtOldPassword.length }}}})
                    </h2>
                    <div class="bg-red-50 dark:bg-red-900/20 border-l-4 border-red-500 p-4 mb-6">
                        <h3 class="font-semibold text-red-800 dark:text-red-200 mb-2">🎯 Issue & Impact</h3>
                        <p class="text-red-700 dark:text-red-300 text-sm mb-3">
                            The KRBTGT account password has not been rotated in over 365 days. This account is used to encrypt and sign all Kerberos tickets in the domain. A compromised KRBTGT password hash enables Golden Ticket attacks, providing persistent, undetectable domain dominance.
                        </p>
                        <h3 class="font-semibold text-red-800 dark:text-red-200 mb-2">⚔️ Attacker Benefit</h3>
                        <p class="text-red-700 dark:text-red-300 text-sm mb-3">
                            With the KRBTGT hash, attackers can forge Kerberos Ticket Granting Tickets (TGTs) for any user, including Domain Admins. These Golden Tickets remain valid even after password resets, providing persistent backdoor access. Detection is nearly impossible as forged tickets appear legitimate to all domain systems.
                        </p>
                        <h3 class="font-semibold text-red-800 dark:text-red-200 mb-2">🔓 Exploitation Method</h3>
                        <p class="text-red-700 dark:text-red-300 text-sm mb-3">
                            Tools: Mimikatz, Rubeus, Impacket's ticketer.py. Once KRBTGT hash is obtained (via DCSync or DC compromise), attackers craft Golden Tickets with arbitrary privileges. Tickets work across all domain resources without re-authentication. Old KRBTGT passwords that haven't been rotated remain valid indefinitely.
                        </p>
                        <h3 class="font-semibold text-red-800 dark:text-red-200 mb-2">💡 Remediation</h3>
                        <p class="text-red-700 dark:text-red-300 text-sm">
                            <strong>Rotate KRBTGT password twice</strong> with a 10-hour wait between rotations to invalidate all existing tickets. Use Microsoft's official script or KRBTGT Reset Toolkit. Establish a regular rotation schedule every 180 days and rotate immediately twice after any suspected compromise.
                        </p>
                    </div>
                    <div class="table-container">
                        <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                            <thead>
                                <tr>
                                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Account Name</th>
                                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Password Last Set</th>
                                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Password Age (days)</th>
                                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Risk</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
                                <tr v-for="account in krbtgtOldPassword" :key="account['SAM Account Name'] || account.SAMAccountName || account.UserName || account.User">
                                    <td class="px-6 py-4 whitespace-nowrap font-medium">{{{{ account['SAM Account Name'] || account.SAMAccountName || account.UserName || account.User || 'krbtgt' }}}}</td>
                                    <td class="px-6 py-4">{{{{ account['Password Last Set'] || account.PasswordLastSet || 'N/A' }}}}</td>
                                    <td class="px-6 py-4">
                                        <span :class="parseInt(account['Password Age (days)']) > 730 ? 'badge badge-critical' : 'badge badge-high'">
                                            {{{{ account['Password Age (days)'] }}}} days
                                        </span>
                                    </td>
                                    <td class="px-6 py-4">
                                        <span class="badge badge-critical">GOLDEN TICKET RISK</span>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Unprotected Privileged Users -->
                <div id="protected-users-section" v-if="unprotectedPrivilegedUsers.length > 0" class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                    <h2 class="text-2xl font-bold text-gray-900 dark:text-white mb-4">
                        <i class="fas fa-shield-alt text-teal-600"></i> Unprotected Privileged Users ({{{{ unprotectedPrivilegedUsers.length }}}})
                    </h2>
                    <div class="bg-teal-50 dark:bg-teal-900/20 border-l-4 border-teal-500 p-4 mb-6">
                        <h3 class="font-semibold text-teal-800 dark:text-teal-200 mb-2">🎯 Issue & Impact</h3>
                        <p class="text-teal-700 dark:text-teal-300 text-sm mb-3">
                            Privileged accounts (Domain Admins, Enterprise Admins, Administrators) not in the Protected Users security group lack critical protections against credential theft attacks. This group enforces non-delegable credentials, NTLMv2-only authentication, Kerberos AES encryption, and restrictions on credential caching.
                        </p>
                        <h3 class="font-semibold text-teal-800 dark:text-teal-200 mb-2">⚔️ Attacker Benefit</h3>
                        <p class="text-teal-700 dark:text-teal-300 text-sm mb-3">
                            Without Protected Users protections, privileged accounts are vulnerable to Pass-the-Hash, Pass-the-Ticket, credential delegation abuse, and offline attacks on weak/legacy encryption. Compromising these accounts grants domain-wide control.
                        </p>
                        <h3 class="font-semibold text-teal-800 dark:text-teal-200 mb-2">🔓 Exploitation Method</h3>
                        <p class="text-teal-700 dark:text-teal-300 text-sm mb-3">
                            Tools: Mimikatz (sekurlsa::logonpasswords, sekurlsa::tickets), Rubeus, Impacket. Extract credentials from LSASS memory, perform Pass-the-Hash/Pass-the-Ticket attacks. Unconstrained/constrained delegation allows ticket theft. RC4 encryption susceptible to offline cracking.
                        </p>
                        <h3 class="font-semibold text-teal-800 dark:text-teal-200 mb-2">💡 Remediation</h3>
                        <p class="text-teal-700 dark:text-teal-300 text-sm">
                            <strong>Add privileged accounts to Protected Users group:</strong> For Windows Server 2012 R2+ domains, add Domain Admins, Enterprise Admins, and other Tier 0 accounts to the "Protected Users" group. This enforces: no NTLM authentication (Kerberos only), no DES/RC4 encryption, no credential delegation, no password caching. Test compatibility before deployment as some legacy applications may break.
                        </p>
                    </div>
                    <div class="table-container">
                        <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                            <thead>
                                <tr>
                                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">SAM Account Name</th>
                                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Name</th>
                                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Status</th>
                                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Last Logon</th>
                                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Risk Level</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
                                <tr v-for="user in unprotectedPrivilegedUsers" :key="user['SAM Account Name']">
                                    <td class="px-6 py-4 whitespace-nowrap font-medium">{{{{ user['SAM Account Name'] }}}}</td>
                                    <td class="px-6 py-4">{{{{ user.Name || 'N/A' }}}}</td>
                                    <td class="px-6 py-4 text-sm">{{{{ user.Status || 'N/A' }}}}</td>
                                    <td class="px-6 py-4 text-sm">{{{{ user['Last Logon'] || 'Never' }}}}</td>
                                    <td class="px-6 py-4">
                                        <span v-if="user['Risk Level'] === 'CRITICAL' || user['Risk Level'] === 'Critical'" class="badge badge-critical">CRITICAL</span>
                                        <span v-else-if="user['Risk Level'] === 'HIGH' || user['Risk Level'] === 'High'" class="badge badge-high">HIGH</span>
                                        <span v-else-if="user['Risk Level'] === 'MEDIUM' || user['Risk Level'] === 'Medium'" class="badge badge-medium">MEDIUM</span>
                                        <span v-else class="badge badge-low">{{{{ user['Risk Level'] || 'LOW' }}}}</span>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Machine Account Quota -->
                <div id="machine-quota-section" v-if="machineAccountQuota > 0" class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                    <h2 class="text-2xl font-bold text-gray-900 dark:text-white mb-4">
                        <i class="fas fa-server text-amber-600"></i> Machine Account Quota ({{{{ machineAccountQuota }}}})
                    </h2>
                    <div class="bg-amber-50 dark:bg-amber-900/20 border-l-4 border-amber-500 p-4 mb-6">
                        <h3 class="font-semibold text-amber-800 dark:text-amber-200 mb-2">🎯 Issue & Impact</h3>
                        <p class="text-amber-700 dark:text-amber-300 text-sm mb-3">
                            The ms-DS-MachineAccountQuota attribute controls how many computer accounts an authenticated user can join to the domain. When set above 0 (default is 10), any domain user can add workstations to Active Directory without administrative privileges, creating unauthorized attack surfaces.
                        </p>
                        <h3 class="font-semibold text-amber-800 dark:text-amber-200 mb-2">⚔️ Attacker Benefit</h3>
                        <p class="text-amber-700 dark:text-amber-300 text-sm mb-3">
                            Attackers with low-privileged access can join rogue computers to the domain, enabling Resource-Based Constrained Delegation (RBCD) attacks, computer account password hash harvesting, Kerberos delegation abuse, and establishing persistent footholds. Rogue computers bypass network access controls and monitoring.
                        </p>
                        <h3 class="font-semibold text-amber-800 dark:text-amber-200 mb-2">🔓 Exploitation Method</h3>
                        <p class="text-amber-700 dark:text-amber-300 text-sm mb-3">
                            Use PowerShell (<code>New-MachineAccount</code>), Impacket's <span class="tool-link">addcomputer.py</span>, or StandIn to add computer accounts. Configure RBCD using PowerView/PowerMad to enable impersonation attacks. Computer accounts have SPNs enabling Silver Ticket attacks and can be used for lateral movement via unconstrained delegation abuse.
                        </p>
                        <h3 class="font-semibold text-amber-800 dark:text-amber-200 mb-2">💡 Remediation</h3>
                        <p class="text-amber-700 dark:text-amber-300 text-sm">
                            <strong>Set ms-DS-MachineAccountQuota to 0:</strong> Use PowerShell: <code>Set-ADDomain -Identity (Get-ADDomain) -Replace @{{"ms-DS-MachineAccountQuota"="0"}}</code> or ADSI Edit to modify the domain object. This prevents non-administrative users from joining computers. Implement controlled computer creation through IT helpdesk workflows with proper approval processes. Regularly audit computer accounts for unauthorized additions using the <code>whenCreated</code> and <code>creator</code> attributes.
                        </p>
                    </div>
                    <div class="table-container">
                        <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                            <thead>
                                <tr>
                                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Attribute</th>
                                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Current Value</th>
                                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Recommended</th>
                                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Risk Level</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
                                <tr>
                                    <td class="px-6 py-4 whitespace-nowrap font-medium">ms-DS-MachineAccountQuota</td>
                                    <td class="px-6 py-4">
                                        <span class="text-red-600 dark:text-red-400 font-bold text-lg">{{{{ machineAccountQuota }}}}</span>
                                    </td>
                                    <td class="px-6 py-4">
                                        <span class="badge badge-none">0</span>
                                    </td>
                                    <td class="px-6 py-4">
                                        <span v-if="machineAccountQuota >= 10" class="badge badge-high">HIGH</span>
                                        <span v-else-if="machineAccountQuota > 0" class="badge badge-medium">MEDIUM</span>
                                        <span v-else class="badge badge-none">NONE</span>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Password Policy Analysis -->
                <div id="password-policy-section" v-if="passwordPolicy.length > 0" class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                    <h2 class="text-2xl font-bold text-gray-900 dark:text-white mb-4">
                        <i class="fas fa-key text-yellow-600"></i> Password Policy Analysis
                    </h2>
                    <div class="bg-orange-50 dark:bg-orange-900/20 border-l-4 border-orange-500 p-4 mb-6">
                        <h3 class="font-semibold text-orange-800 dark:text-orange-200 mb-2">🎯 Issue & Impact</h3>
                        <p class="text-orange-700 dark:text-orange-300 text-sm mb-3">
                            Weak password policies allow attackers to compromise accounts through brute-force attacks, password guessing, and credential stuffing. Inadequate complexity requirements, long password ages, and weak lockout policies create exploitable vulnerabilities.
                        </p>
                        <h3 class="font-semibold text-orange-800 dark:text-orange-200 mb-2">⚔️ Attacker Benefit</h3>
                        <p class="text-orange-700 dark:text-orange-300 text-sm mb-3">
                            Weak policies enable password spraying attacks, where attackers try common passwords against many accounts. Long password ages mean compromised passwords remain valid indefinitely. Weak lockout thresholds allow unlimited brute-force attempts.
                        </p>
                        <h3 class="font-semibold text-orange-800 dark:text-orange-200 mb-2">🔓 Exploitation Method</h3>
                        <p class="text-orange-700 dark:text-orange-300 text-sm mb-3">
                            Tools: Hydra, Medusa, CrackMapExec. Attackers enumerate users, spray common passwords, escalate with compromised credentials. No complexity = simple passwords work.
                        </p>
                        <h3 class="font-semibold text-orange-800 dark:text-orange-200 mb-2">💡 Remediation</h3>
                        <p class="text-orange-700 dark:text-orange-300 text-sm">
                            <strong>Implement CIS-compliant password policy:</strong> Minimum 14 characters, maximum age 365 days (90 for privileged accounts), password history 24, lockout threshold 5 attempts, lockout duration 15 minutes. Enable password complexity requirements. Consider passphrase policy over traditional complexity. Implement Fine-Grained Password Policies (FGPP) for privileged accounts with stricter requirements.
                        </p>
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        <div v-for="policy in passwordPolicy" :key="policy.Policy"
                             class="border rounded-lg p-4"
                             :class="getCISComplianceClass(policy)">
                            <div class="text-sm text-gray-600 dark:text-gray-300 mb-2">{{{{ policy.Policy }}}}</div>
                            <div class="text-xl font-bold text-gray-900 dark:text-white mb-1">{{{{ policy['Current Value'] }}}}</div>
                            <div class="text-xs text-gray-500 dark:text-gray-400">
                                <span v-if="policy['CIS Benchmark 2024-25'] && policy['CIS Benchmark 2024-25'] !== 'N/A' && policy['CIS Benchmark 2024-25'] !== '-'">
                                    CIS: {{{{ policy['CIS Benchmark 2024-25'] }}}}
                                </span>
                                <span v-else class="text-gray-400">No CIS benchmark</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>


            <!-- ADCS Templates Tab -->
            <div v-if="activeTab === 'adcs'" class="space-y-6">
                <div id="adcs-templates-table" class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                    <h2 class="text-2xl font-bold text-gray-900 dark:text-white mb-4">
                        <i class="fas fa-certificate text-orange-600"></i> Certificate Templates (ADCS)
                    </h2>
                    <p class="text-gray-600 dark:text-gray-400 mb-4">
                        Active Directory Certificate Services templates and their security posture.
                    </p>
                                        <div class="flex justify-between items-center mb-6">
                        <div class="flex gap-4">
                            <select v-model="certTemplateFilter" 
                                    class="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg dark:bg-gray-700 dark:text-white">
                                <option value="all">All Templates</option>
                                <option value="vulnerable">ESC Vulnerable Only</option>
                                <option value="non-vulnerable">Non-Vulnerable Only</option>
                            </select>
                            <select v-model="certTemplateRiskFilter" 
                                    class="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg dark:bg-gray-700 dark:text-white">
                                <option value="risk-gt-none">At Risk (> None)</option>
                                <option value="all">All Risk Levels</option>
                                <option value="CRITICAL">Critical Only</option>
                                <option value="HIGH">High Only</option>
                                <option value="MEDIUM">Medium Only</option>
                                <option value="LOW">Low Only</option>
                            </select>
                        </div>
                    </div>
                    <div class="table-container">
                        <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                            <thead>
                                <tr>
                                    <th @click="sortCertTemplates('Template Name')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        Template Name
                                        <i v-if="certTemplateSortColumn === 'Template Name'" :class="certTemplateSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th @click="sortCertTemplates('Risk Factors')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        Risk Factors
                                        <i v-if="certTemplateSortColumn === 'Risk Factors'" :class="certTemplateSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th @click="sortCertTemplates('Risk Level')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        Risk Level
                                        <i v-if="certTemplateSortColumn === 'Risk Level'" :class="certTemplateSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th @click="sortCertTemplates('ESC Vulnerabilities')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        ESC Vulnerabilities
                                        <i v-if="certTemplateSortColumn === 'ESC Vulnerabilities'" :class="certTemplateSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th @click="sortCertTemplates('Enrollment Rights')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        Enrollment Rights
                                        <i v-if="certTemplateSortColumn === 'Enrollment Rights'" :class="certTemplateSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
                                <tr v-for="template in paginatedCertTemplates" :key="template['Template Name']">
                                    <td class="px-6 py-4 whitespace-nowrap font-medium">{{{{ template['Template Name'] }}}}</td>
                                    <td class="px-6 py-4 text-sm">{{{{ template['Risk Factors'] !== 'None' ? template['Risk Factors'] : '-' }}}}</td>
                                    <td class="px-6 py-4">
                                        <span v-if="template['Risk Level'] === 'CRITICAL'" class="badge badge-critical">CRITICAL</span>
                                        <span v-else-if="template['Risk Level'] === 'HIGH'" class="badge badge-high">HIGH</span>
                                        <span v-else-if="template['Risk Level'] && (template['Risk Level'] === 'MEDIUM' || template['Risk Level'] === 'Medium')" class="badge badge-medium">MEDIUM</span>
                                        <span v-else-if="template['Risk Level'] && (template['Risk Level'] === 'LOW' || template['Risk Level'] === 'Low')" class="badge badge-low">LOW</span>
                                        <span v-else class="badge badge-none">None</span>
                                    </td>
                                    <td class="px-6 py-4 text-sm">{{{{ template['ESC Vulnerabilities'] || 'None' }}}}</td>
                                    <td class="px-6 py-4 text-sm">{{{{ template['Enrollment Rights'] || 'N/A' }}}}</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                    <div v-if="filteredCertTemplates.length > itemsPerPage" class="flex justify-between items-center py-4">
                        <div class="text-sm text-gray-500 dark:text-gray-400">
                            Showing {{{{ ((certTemplatePage - 1) * itemsPerPage) + 1 }}}} to {{{{ Math.min(certTemplatePage * itemsPerPage, filteredCertTemplates.length) }}}} of {{{{ filteredCertTemplates.length }}}} templates
                        </div>
                        <div class="flex gap-2">
                            <button @click="certTemplatePage = Math.max(1, certTemplatePage - 1)" :disabled="certTemplatePage === 1" 
                                    class="px-3 py-1 rounded bg-blue-600 text-white disabled:bg-gray-400">
                                <i class="fas fa-chevron-left"></i> Previous
                            </button>
                            <span class="px-3 py-1">Page {{{{ certTemplatePage }}}} of {{{{ Math.ceil(filteredCertTemplates.length / itemsPerPage) }}}}</span>
                            <button @click="certTemplatePage = Math.min(Math.ceil(filteredCertTemplates.length / itemsPerPage), certTemplatePage + 1)" 
                                    :disabled="certTemplatePage >= Math.ceil(filteredCertTemplates.length / itemsPerPage)"
                                    class="px-3 py-1 rounded bg-blue-600 text-white disabled:bg-gray-400">
                                Next <i class="fas fa-chevron-right"></i>
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Users Tab -->
            <div v-if="activeTab === 'users'" class="space-y-6">
                <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                    <div class="flex justify-between items-center mb-6">
                        <h2 class="text-2xl font-bold text-gray-900 dark:text-white">
                            <i class="fas fa-users"></i> User Accounts
                        </h2>
                        <div class="flex gap-4">
                            <input v-model="userSearch" 
                                   type="text" 
                                   placeholder="Search users..."
                                   class="search-input px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg dark:bg-gray-700 dark:text-white">
                            <select v-model="userFilter" 
                                    class="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg dark:bg-gray-700 dark:text-white">
                                <option value="all">All Users</option>
                                <option value="enabled">Enabled Only</option>
                                <option value="disabled">Disabled Only</option>
                                <option value="never_expires">Password Never Expires</option>
                                <option value="must_change">Must Change Password</option>
                                <option value="privileged">Privileged</option>
                                <option value="dormant">Dormant (90+ days)</option>
                                <option value="cannot_change">Cannot Change Password</option>
                                <option value="never_logged">Never Logged In</option>
                            </select>
                        </div>
                    </div>

                    <!-- User Stats -->
                    <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                        <div @click="userFilter = 'enabled'" class="bg-blue-50 dark:bg-blue-900/20 rounded p-4 text-center cursor-pointer hover:shadow-lg transition-shadow">
                            <div class="text-2xl font-bold text-blue-600">{{{{ enabledUsers.length }}}}</div>
                            <div class="text-sm text-gray-600 dark:text-gray-400">Enabled</div>
                        </div>
                        <div @click="userFilter = 'disabled'" class="bg-gray-50 dark:bg-gray-700 rounded p-4 text-center cursor-pointer hover:shadow-lg transition-shadow">
                            <div class="text-2xl font-bold text-gray-600">{{{{ users.length - enabledUsers.length }}}}</div>
                            <div class="text-sm text-gray-600 dark:text-gray-400">Disabled</div>
                        </div>
                        <div @click="userFilter = 'never_expires'" class="bg-yellow-50 dark:bg-yellow-900/20 rounded p-4 text-center cursor-pointer hover:shadow-lg transition-shadow">
                            <div class="text-2xl font-bold text-yellow-600">{{{{ passwordNeverExpires.length }}}}</div>
                            <div class="text-sm text-gray-600 dark:text-gray-400">Never Expires</div>
                        </div>
                        <div @click="userFilter = 'must_change'" class="bg-red-50 dark:bg-red-900/20 rounded p-4 text-center cursor-pointer hover:shadow-lg transition-shadow">
                            <div class="text-2xl font-bold text-red-600">{{{{ mustChangePassword.length }}}}</div>
                            <div class="text-sm text-gray-600 dark:text-gray-400">Must Change Pwd</div>
                        </div>
                        <div @click="userFilter = 'cannot_change'" class="bg-orange-50 dark:bg-orange-900/20 rounded p-4 text-center cursor-pointer hover:shadow-lg transition-shadow">
                            <div class="text-2xl font-bold text-orange-600">{{{{ cannotChangePassword.length }}}}</div>
                            <div class="text-sm text-gray-600 dark:text-gray-400">Cannot Change Pwd</div>
                        </div>
                        <div @click="userFilter = 'never_logged'" class="bg-purple-50 dark:bg-purple-900/20 rounded p-4 text-center cursor-pointer hover:shadow-lg transition-shadow">
                            <div class="text-2xl font-bold text-purple-600">{{{{ neverLoggedIn.length }}}}</div>
                            <div class="text-sm text-gray-600 dark:text-gray-400">Never Logged In</div>
                        </div>
                    </div>

                    <!-- Users Table -->
                    <div class="table-container">
                        <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                            <thead>
                                <tr>
                                    <th @click="sortUsers('SAMAccountName')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        User
                                        <i v-if="userSortColumn === 'SAMAccountName'" :class="userSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th @click="sortUsers('Name')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        Name
                                        <i v-if="userSortColumn === 'Name'" :class="userSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th @click="sortUsers('Enabled')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        Status
                                        <i v-if="userSortColumn === 'Enabled'" :class="userSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th @click="sortUsers('Password Age (days)')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        Pwd Age
                                        <i v-if="userSortColumn === 'Password Age (days)'" :class="userSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Flags</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
                                <tr v-for="user in paginatedUsers" :key="user.UserName">
                                    <td class="px-6 py-4 whitespace-nowrap font-medium">
                                        {{{{ user.UserName }}}}
                                    </td>
                                    <td class="px-6 py-4">{{{{ user.Name }}}}</td>
                                    <td class="px-6 py-4">
                                        <span :class="(user.Enabled === 'True' || user.Enabled === 'TRUE') ? 'badge badge-low' : 'badge badge-none'">
                                            {{{{ (user.Enabled === 'True' || user.Enabled === 'TRUE') ? 'Enabled' : 'Disabled' }}}}
                                        </span>
                                    </td>
                                    <td class="px-6 py-4">{{{{ user['Password Age (days)'] || 'N/A' }}}}</td>
                                    <td class="px-6 py-4">
                                        <div class="flex flex-wrap gap-1 text-xs">
                                            <span v-if="user.PasswordNeverExpires === 'True' || user.PasswordNeverExpires === 'TRUE' || user['Password Never Expires'] === 'True' || user['Password Never Expires'] === 'TRUE'" class="badge badge-amber">Never Expires</span>
                                            <span v-if="user.PasswordExpired === 'True' || user.PasswordExpired === 'TRUE'" class="badge badge-critical">Expired</span>
                                            <span v-if="user['Dormant (> 90 days)'] === 'True' || user['Dormant (> 90 days)'] === 'TRUE'" class="badge badge-purple">Dormant</span>
                                            <span v-if="user['Must Change Password at Logon'] === 'True' || user['Must Change Password at Logon'] === 'TRUE'" class="badge badge-pink">Must Change Pwd</span>
                                            <span v-if="user['Cannot Change Password'] === 'True' || user['Cannot Change Password'] === 'TRUE'" class="badge badge-cyan">Cannot Change</span>
                                            <span v-if="user['Never Logged in'] === 'True' || user['Never Logged in'] === 'TRUE'" class="badge badge-indigo">Never Logged</span>
                                            <span v-if="user.AdminCount === '1'" class="badge badge-high">Admin</span>
                                        </div>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                        <div v-if="filteredUsers.length > itemsPerPage" class="flex justify-between items-center py-4">
                            <div class="text-sm text-gray-500 dark:text-gray-400">
                                Showing {{{{ ((userPage - 1) * itemsPerPage) + 1 }}}} to {{{{ Math.min(userPage * itemsPerPage, filteredUsers.length) }}}} of {{{{ filteredUsers.length }}}} users
                            </div>
                            <div class="flex gap-2">
                                <button @click="userPage = Math.max(1, userPage - 1)" :disabled="userPage === 1" 
                                        class="px-3 py-1 rounded bg-blue-600 text-white disabled:bg-gray-400">
                                    <i class="fas fa-chevron-left"></i> Previous
                                </button>
                                <span class="px-3 py-1">Page {{{{ userPage }}}} of {{{{ Math.ceil(filteredUsers.length / itemsPerPage) }}}}</span>
                                <button @click="userPage = Math.min(Math.ceil(filteredUsers.length / itemsPerPage), userPage + 1)" 
                                        :disabled="userPage >= Math.ceil(filteredUsers.length / itemsPerPage)"
                                        class="px-3 py-1 rounded bg-blue-600 text-white disabled:bg-gray-400">
                                    Next <i class="fas fa-chevron-right"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Computers Tab -->
            <div v-if="activeTab === 'computers'" class="space-y-6">
                <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
                    <div class="flex justify-between items-center mb-6">
                        <h2 class="text-2xl font-bold text-gray-900 dark:text-white">
                            <i class="fas fa-desktop"></i> Computer Accounts
                        </h2>
                        <div class="flex gap-4">
                            <input v-model="computerSearch" 
                                   type="text" 
                                   placeholder="Search computers..."
                                   class="search-input px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg dark:bg-gray-700 dark:text-white">
                            <select v-model="computerFilter" 
                                    class="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg dark:bg-gray-700 dark:text-white">
                                <option value="all">All Computers</option>
                                <option value="enabled">Enabled Only</option>
                                <option value="disabled">Disabled Only</option>
                                <option value="servers">Servers</option>
                                <option value="workstations">Workstations</option>
                                <option value="dormant">Dormant (90+ days)</option>
                                <option value="old_password">Old Password (180+ days)</option>
                                <option value="delegated">Delegation Enabled</option>
                            </select>
                        </div>
                    </div>

                    <!-- Computer Stats -->
                    <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                        <div @click="computerFilter = 'enabled'" class="bg-blue-50 dark:bg-blue-900/20 rounded p-4 text-center cursor-pointer hover:shadow-lg transition-shadow">
                            <div class="text-2xl font-bold text-blue-600">{{{{ enabledComputers.length }}}}</div>
                            <div class="text-sm text-gray-600 dark:text-gray-400">Enabled</div>
                        </div>
                        <div @click="computerFilter = 'disabled'" class="bg-gray-50 dark:bg-gray-700 rounded p-4 text-center cursor-pointer hover:shadow-lg transition-shadow">
                            <div class="text-2xl font-bold text-gray-600">{{{{ disabledComputers.length }}}}</div>
                            <div class="text-sm text-gray-600 dark:text-gray-400">Disabled</div>
                        </div>
                        <div @click="computerFilter = 'servers'" class="bg-green-50 dark:bg-green-900/20 rounded p-4 text-center cursor-pointer hover:shadow-lg transition-shadow">
                            <div class="text-2xl font-bold text-green-600">{{{{ computerServers.length }}}}</div>
                            <div class="text-sm text-gray-600 dark:text-gray-400">Servers</div>
                        </div>
                        <div @click="computerFilter = 'workstations'" class="bg-purple-50 dark:bg-purple-900/20 rounded p-4 text-center cursor-pointer hover:shadow-lg transition-shadow">
                            <div class="text-2xl font-bold text-purple-600">{{{{ computerWorkstations.length }}}}</div>
                            <div class="text-sm text-gray-600 dark:text-gray-400">Workstations</div>
                        </div>
                        <div @click="computerFilter = 'dormant'" class="bg-orange-50 dark:bg-orange-900/20 rounded p-4 text-center cursor-pointer hover:shadow-lg transition-shadow">
                            <div class="text-2xl font-bold text-orange-600">{{{{ dormantComputers.length }}}}</div>
                            <div class="text-sm text-gray-600 dark:text-gray-400">Dormant (90+ days)</div>
                        </div>
                        <div @click="computerFilter = 'old_password'" class="bg-red-50 dark:bg-red-900/20 rounded p-4 text-center cursor-pointer hover:shadow-lg transition-shadow">
                            <div class="text-2xl font-bold text-red-600">{{{{ oldPasswordComputers.length }}}}</div>
                            <div class="text-sm text-gray-600 dark:text-gray-400">Old Password (180+ days)</div>
                        </div>
                        <div @click="computerFilter = 'delegated'" class="bg-yellow-50 dark:bg-yellow-900/20 rounded p-4 text-center cursor-pointer hover:shadow-lg transition-shadow">
                            <div class="text-2xl font-bold text-yellow-600">{{{{ delegatedComputers.length }}}}</div>
                            <div class="text-sm text-gray-600 dark:text-gray-400">Delegation Enabled</div>
                        </div>
                    </div>

                    <!-- Computers Table -->
                    <div class="table-container">
                        <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                            <thead>
                                <tr>
                                    <th @click="sortComputers('Name')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        Computer
                                        <i v-if="computerSortColumn === 'Name'" :class="computerSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th @click="sortComputers('DNSHostName')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        DNS Hostname
                                        <i v-if="computerSortColumn === 'DNSHostName'" :class="computerSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th @click="sortComputers('IPv4Address')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        IPv4
                                        <i v-if="computerSortColumn === 'IPv4Address'" :class="computerSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th @click="sortComputers('Operating System')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        OS
                                        <i v-if="computerSortColumn === 'Operating System'" :class="computerSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th @click="sortComputers('Enabled')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        Status
                                        <i v-if="computerSortColumn === 'Enabled'" :class="computerSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th @click="sortComputers('Password Age (days)')" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700">
                                        Pwd Age
                                        <i v-if="computerSortColumn === 'Password Age (days)'" :class="computerSortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down'" class="ml-1"></i>
                                        <i v-else class="fas fa-sort ml-1 opacity-30"></i>
                                    </th>
                                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Flags</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
                                <tr v-for="computer in paginatedComputers" :key="computer.Name">
                                    <td class="px-6 py-4 whitespace-nowrap font-medium">{{{{ computer.Name }}}}</td>
                                    <td class="px-6 py-4 text-sm">{{{{ computer.DNSHostName || '-' }}}}</td>
                                    <td class="px-6 py-4 text-sm">{{{{ computer.IPv4Address || '-' }}}}</td>
                                    <td class="px-6 py-4 text-sm">{{{{ computer['Operating System'] || '-' }}}}</td>
                                    <td class="px-6 py-4">
                                        <span :class="(computer.Enabled === 'True' || computer.Enabled === 'TRUE') ? 'badge badge-low' : 'badge badge-none'">
                                            {{{{ (computer.Enabled === 'True' || computer.Enabled === 'TRUE') ? 'Enabled' : 'Disabled' }}}}
                                        </span>
                                    </td>
                                    <td class="px-6 py-4">{{{{ computer['Password Age (days)'] || 'N/A' }}}}</td>
                                    <td class="px-6 py-4">
                                        <div class="flex flex-wrap gap-1 text-xs">
                                            <span v-if="computer['Dormant (> 90 days)'] === 'True' || computer['Dormant (> 90 days)'] === 'TRUE'" class="badge badge-purple">Dormant</span>
                                            <span v-if="computer['Password Age (> 180 days)'] === 'True' || computer['Password Age (> 180 days)'] === 'TRUE'" class="badge badge-amber">Old Password</span>
                                            <span v-if="computer['Delegation Type'] && computer['Delegation Type'] !== '' && computer['Delegation Type'] !== 'None'" class="badge badge-critical">{{{{ computer['Delegation Type'] }}}}</span>
                                            <span v-if="computer['Primary Group ID'] === '516'" class="badge badge-high">Domain Controller</span>
                                        </div>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                    <div v-if="filteredComputers.length > itemsPerPage" class="flex justify-between items-center py-4">
                        <div class="text-sm text-gray-500 dark:text-gray-400">
                            Showing {{{{ ((computerPage - 1) * itemsPerPage) + 1 }}}} to {{{{ Math.min(computerPage * itemsPerPage, filteredComputers.length) }}}} of {{{{ filteredComputers.length }}}} computers
                        </div>
                        <div class="flex gap-2">
                            <button @click="computerPage = Math.max(1, computerPage - 1)" :disabled="computerPage === 1" 
                                    class="px-3 py-1 rounded bg-blue-600 text-white disabled:bg-gray-400">
                                <i class="fas fa-chevron-left"></i> Previous
                            </button>
                            <span class="px-3 py-1">Page {{{{ computerPage }}}} of {{{{ Math.ceil(filteredComputers.length / itemsPerPage) }}}}</span>
                            <button @click="computerPage = Math.min(Math.ceil(filteredComputers.length / itemsPerPage), computerPage + 1)" 
                                    :disabled="computerPage >= Math.ceil(filteredComputers.length / itemsPerPage)"
                                    class="px-3 py-1 rounded bg-blue-600 text-white disabled:bg-gray-400">
                                Next <i class="fas fa-chevron-right"></i>
                            </button>
                        </div>
                    </div>
                </div>
            </div>

        </main>

        <!-- Footer -->
        <footer class="bg-white dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700 mt-12">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 text-center text-gray-500 dark:text-gray-400">
                <p>PyADRecon Dashboard | Generated with ❤️</p>
            </div>
        </footer>
    </div>

    <script>
        try {{
            const {{ createApp }} = Vue;
            
            // Embedded data
            const csvData = {data_json};
            
            createApp({{
            data() {{
                return {{
                    darkMode: true,
                    activeTab: 'overview',
                    activeView: 'all',
                    userPage: 1,
                    computerPage: 1,
                    certTemplatePage: 1,
                    kerberoastPage: 1,
                    asrepPage: 1,
                    lapsPage: 1,
                    itemsPerPage: 50,
                    certTemplateFilter: 'all',
                    certTemplateRiskFilter: 'risk-gt-none',
                    userSearch: '',
                    computerSearch: '',
                    userFilter: 'all',
                    computerFilter: 'all',
                    certTemplateSortColumn: null,
                    certTemplateSortDirection: 'asc',
                    vulnCertTemplateSortColumn: null,
                    vulnCertTemplateSortDirection: 'asc',
                    kerberoastSortColumn: null,
                    kerberoastSortDirection: 'asc',
                    asrepSortColumn: null,
                    asrepSortDirection: 'asc',
                    cleartextSortColumn: null,
                    cleartextSortDirection: 'asc',
                    lapsSortColumn: null,
                    lapsSortDirection: 'asc',
                    userSortColumn: null,
                    userSortDirection: 'asc',
                    computerSortColumn: null,
                    computerSortDirection: 'asc',
                    tabs: [
                        {{ id: 'overview', label: 'Overview', icon: 'fas fa-home', count: null }},
                        {{ id: 'findings', label: 'Security Findings', icon: 'fas fa-bug', count: null }},
                        {{ id: 'users', label: 'Users', icon: 'fas fa-users', count: null }},
                        {{ id: 'computers', label: 'Computers', icon: 'fas fa-desktop', count: null }},
                        {{ id: 'adcs', label: 'ADCS Templates', icon: 'fas fa-certificate', count: null }}
                    ]
                }}
            }},
            computed: {{
                users() {{
                    return csvData.Users || [];
                }},
                computers() {{
                    return csvData.Computers || [];
                }},
                certTemplates() {{
                    return csvData.CertificateTemplates || [];
                }},
                
                vulnerableCertTemplates() {{
                    let filtered = this.certTemplates.filter(t => t['ESC Vulnerabilities'] && t['ESC Vulnerabilities'] !== 'None' && t['ESC Vulnerabilities'].trim() !== '');
                    
                    // Apply sorting
                    if (this.vulnCertTemplateSortColumn) {{
                        const direction = this.vulnCertTemplateSortDirection === 'asc' ? 1 : -1;
                        const column = this.vulnCertTemplateSortColumn;
                        
                        filtered.sort((a, b) => {{
                            // Special handling for Risk Level
                            if (column === 'Risk Level') {{
                                const riskPriority = {{
                                    'CRITICAL': 0,
                                    'HIGH': 1,
                                    'MEDIUM': 2,
                                    'Medium': 2,
                                    'LOW': 3,
                                    'Low': 3,
                                    'None': 4
                                }};
                                const aPriority = riskPriority[a[column]] ?? 999;
                                const bPriority = riskPriority[b[column]] ?? 999;
                                return (aPriority - bPriority) * direction;
                            }}
                            
                            // Normal string comparison
                            const aValue = (a[column] || '').toString().toLowerCase();
                            const bValue = (b[column] || '').toString().toLowerCase();
                            
                            if (aValue < bValue) return -1 * direction;
                            if (aValue > bValue) return 1 * direction;
                            return 0;
                        }});
                    }}
                    
                    return filtered;
                }},
                kerberoastable() {{
                    return csvData.Kerberoastable || [];
                }},
                asreproastable() {{
                    return csvData.ASREPRoastable || [];
                }},
                trusts() {{
                    return csvData.Trusts || [];
                }},
                domain() {{
                    return csvData.Domain || [];
                }},
                domainControllers() {{
                    return csvData.DomainControllers || [];
                }},
                groups() {{
                    return csvData.Groups || [];
                }},
                groupMembers() {{
                    return csvData.GroupMembers || [];
                }},
                laps() {{
                    return csvData.LAPS || [];
                }},
                passwordPolicy() {{
                    return csvData.PasswordPolicy || [];
                }},
                failedCISControls() {{
                    let failedCount = 0;
                    this.passwordPolicy.forEach(policy => {{
                        if (this.checkCISCompliance(policy) === 'fail') {{
                            failedCount++;
                        }}
                    }});
                    return failedCount;
                }},
                gmsa() {{
                    return csvData.gMSA || [];
                }},
                gpos() {{
                    return csvData.GPOs || [];
                }},
                certificateAuthorities() {{
                    return csvData.CertificateAuthorities || [];
                }},
                printers() {{
                    return csvData.Printers || [];
                }},
                ous() {{
                    return csvData.OUs || [];
                }},
                sites() {{
                    return csvData.Sites || [];
                }},
                subnets() {{
                    return csvData.Subnets || [];
                }},
                fineGrainedPasswordPolicy() {{
                    return csvData.FineGrainedPasswordPolicy || [];
                }},
                forest() {{
                    return csvData.Forest || [];
                }},
                krbtgt() {{
                    return csvData.krbtgt || [];
                }},
                protectedGroups() {{
                    return csvData.ProtectedGroups || [];
                }},
                
                aboutInfo() {{
                    const about = csvData.AboutPyADRecon || [];
                    if (about.length === 0) return {{ version: '', user: '', computer: '', domain: '', github: '' }};
                    
                    const versionRow = about.find(r => r.Category === 'PyADRecon-ADWS Version');
                    const userRow = about.find(r => r.Category === 'Executed By');
                    const computerRow = about.find(r => r.Category === 'Executed From');
                    const domainRow = about.find(r => r.Category === 'Target Domain');
                    const githubRow = about.find(r => r.Category === 'GitHub Repository');
                    
                    return {{
                        version: versionRow ? versionRow.Value : '',
                        user: userRow ? userRow.Value : '',
                        computer: computerRow ? computerRow.Value : '',
                        domain: domainRow ? domainRow.Value : '',
                        github: githubRow ? githubRow.Value : ''
                    }};
                }},
                
                enabledUsers() {{
                    return this.users.filter(u => u.Enabled === 'True' || u.Enabled === 'TRUE');
                }},
                enabledComputers() {{
                    return this.computers.filter(c => c.Enabled === 'True' || c.Enabled === 'TRUE');
                }},
                disabledComputers() {{
                    return this.computers.filter(c => c.Enabled === 'False' || c.Enabled === 'FALSE' || !c.Enabled);
                }},
                dormantComputers() {{
                    return this.computers.filter(c => {{
                        const logonAge = parseInt(c['Logon Age (days)']);
                        return !isNaN(logonAge) && logonAge > 90;
                    }});
                }},
                computerServers() {{
                    return this.computers.filter(c => c['Operating System'] && c['Operating System'].toLowerCase().includes('server'));
                }},
                computerWorkstations() {{
                    return this.computers.filter(c => c['Operating System'] && !c['Operating System'].toLowerCase().includes('server') && c['Operating System'] !== '');
                }},
                oldPasswordComputers() {{
                    return this.computers.filter(c => {{
                        const pwdAge = parseInt(c['Password Age (days)']);
                        return !isNaN(pwdAge) && pwdAge > 180;
                    }});
                }},
                delegatedComputers() {{
                    return this.computers.filter(c => c['Delegation Type'] && c['Delegation Type'] !== '' && c['Delegation Type'] !== 'None');
                }},
                privilegedUsers() {{
                    return this.users.filter(u => u.AdminCount === '1');
                }},
                passwordNeverExpires() {{
                    return this.users.filter(u => u.PasswordNeverExpires === 'True' || u.PasswordNeverExpires === 'TRUE' || u['Password Never Expires'] === 'True' || u['Password Never Expires'] === 'TRUE');
                }},
                mustChangePassword() {{
                    return this.users.filter(u => u.PasswordExpired === 'True' || u.PasswordExpired === 'TRUE' || u['Must Change Password at Logon'] === 'True' || u['Must Change Password at Logon'] === 'TRUE');
                }},
                cannotChangePassword() {{
                    return this.users.filter(u => u['Cannot Change Password'] === 'True' || u['Cannot Change Password'] === 'TRUE');
                }},
                neverLoggedIn() {{
                    return this.users.filter(u => u['Never Logged in'] === 'True' || u['Never Logged in'] === 'TRUE');
                }},
                
                vulnerableTemplates() {{
                    return this.certTemplates.filter(t => 
                        t['Risk Level'] && t['Risk Level'] !== 'None' && t['Risk Level'] !== 'Low'
                    );
                }},
                
                criticalTemplates() {{
                    return this.certTemplates.filter(t => t['Risk Level'] === 'CRITICAL');
                }},
                
                highRiskTemplates() {{
                    return this.certTemplates.filter(t => t['Risk Level'] === 'HIGH');
                }},
                
                mediumRiskTemplates() {{
                    return this.certTemplates.filter(t => t['Risk Level'] === 'MEDIUM' || t['Risk Level'] === 'Medium');
                }},
                
                usersWithPasswordsInInfo() {{
                    const pwdPatterns = /pass(?:w(?:or)?d)?[\\s:=]+[\\S]+|pwd[\\s:=]+[\\S]+/i;
                    let filtered = this.users.filter(u => 
                        (u.Description && pwdPatterns.test(u.Description)) ||
                        (u.Info && pwdPatterns.test(u.Info))
                    );
                    
                    // Apply sorting
                    if (this.cleartextSortColumn) {{
                        const direction = this.cleartextSortDirection === 'asc' ? 1 : -1;
                        const column = this.cleartextSortColumn;
                        
                        filtered.sort((a, b) => {{
                            // Normal string comparison
                            const aValue = (a[column] || '').toString().toLowerCase();
                            const bValue = (b[column] || '').toString().toLowerCase();
                            
                            if (aValue < bValue) return -1 * direction;
                            if (aValue > bValue) return 1 * direction;
                            return 0;
                        }});
                    }}
                    
                    return filtered;
                }},
                
                dormantUsers() {{
                    return this.users.filter(u => {{
                        const logonAge = parseInt(u['Logon Age (days)']);
                        return !isNaN(logonAge) && logonAge > 180;
                    }});
                }},
                
                staleComputers() {{
                    return this.computers.filter(c => {{
                        const logonAge = parseInt(c['Logon Age (days)']);
                        return !isNaN(logonAge) && logonAge > 90;
                    }});
                }},
                
                lapsReadable() {{
                    return csvData.LAPS ? csvData.LAPS.filter(l => l.Readable === 'True' || l.Readable === 'TRUE') : [];
                }},
                
                krbtgtOldPassword() {{
                    return this.krbtgt.filter(k => {{
                        const pwdAge = parseInt(k['Password Age (days)']);
                        return !isNaN(pwdAge) && pwdAge > 180;
                    }});
                }},
                
                unprotectedPrivilegedUsers() {{
                    return this.protectedGroups.filter(u => {{
                        // Users not in Protected Users group with Risk Level > Low
                        const notInProtectedUsers = u['In Protected Users Group'] === 'No' || u['In Protected Users Group'] === 'NO';
                        const isUser = u.Type === 'User' || u.Type === 'USER';
                        const riskLevel = (u['Risk Level'] || '').toUpperCase();
                        const highRisk = riskLevel === 'MEDIUM' || riskLevel === 'HIGH' || riskLevel === 'CRITICAL';
                        return isUser && notInProtectedUsers && highRisk;
                    }});
                }},
                
                machineAccountQuota() {{
                    if (this.domain.length > 0) {{
                        // Domain.csv has Category/Value format
                        const quotaEntry = this.domain.find(d => d.Category === 'ms-DS-MachineAccountQuota');
                        if (quotaEntry) {{
                            const quota = parseInt(quotaEntry.Value);
                            return isNaN(quota) ? 0 : quota;
                        }}
                    }}
                    return 0;
                }},
                
                lapsEnabled() {{
                    return this.laps.filter(l => l['LAPS Enabled'] === 'True' || l['LAPS Enabled'] === 'TRUE');
                }},
                
                serviceAccounts() {{
                    return this.users.filter(u => u.ServicePrincipalNames && u.ServicePrincipalNames !== '');
                }},
                
                weakPasswordPolicy() {{
                    if (this.passwordPolicy.length === 0) return [];
                    const issues = [];
                    
                    // Find policy values by Policy name
                    const minLengthPolicy = this.passwordPolicy.find(p => p.Policy && p.Policy.includes('Minimum password length'));
                    const maxAgePolicy = this.passwordPolicy.find(p => p.Policy && p.Policy.includes('Maximum password age'));
                    const lockoutPolicy = this.passwordPolicy.find(p => p.Policy && p.Policy.includes('Account lockout threshold'));
                    
                    if (minLengthPolicy) {{
                        const minLength = parseInt(minLengthPolicy['Current Value']);
                        if (!isNaN(minLength) && minLength < 14) {{
                            issues.push({{ field: 'Min Length', value: minLengthPolicy['Current Value'], issue: 'Below 14 characters' }});
                        }}
                    }}
                    
                    if (maxAgePolicy) {{
                        const maxAge = parseInt(maxAgePolicy['Current Value']);
                        if (!isNaN(maxAge) && maxAge > 90) {{
                            issues.push({{ field: 'Max Age', value: maxAgePolicy['Current Value'], issue: 'Exceeds 90 days' }});
                        }}
                    }}
                    
                    const complexityPolicy = this.passwordPolicy.find(p => p.Policy && p.Policy.includes('complexity'));
                    if (complexityPolicy) {{
                        const complexityValue = complexityPolicy['Current Value'];
                        if (complexityValue === 'FALSE' || complexityValue === 'False' || complexityValue === 'false') {{
                            issues.push({{ field: 'Complexity', value: complexityValue, issue: 'Complexity requirements disabled' }});
                        }}
                    }}
                    
                    if (lockoutPolicy) {{
                        const lockout = parseInt(lockoutPolicy['Current Value']);
                        if (isNaN(lockout) || lockout === 0) {{
                            issues.push({{ field: 'Lockout', value: lockoutPolicy['Current Value'] || 'Disabled', issue: 'No account lockout' }});
                        }}
                    }}
                    
                    return issues;
                }},
                
                securityIssuesCount() {{
                    let count = 0;
                    if (this.vulnerableCertTemplates.length > 0) count++; // ADCS ESC Vulnerabilities
                    if (this.kerberoastable.length > 0) count++; // Kerberoastable
                    if (this.asreproastable.length > 0) count++; // ASREPRoastable
                    if (this.usersWithPasswordsInInfo.length > 0) count++; // Passwords in user info
                    if (this.lapsReadable.length > 0) count++; // LAPS Readable
                    if (this.passwordPolicy.length > 0) count++; // Password Policy
                    if (this.krbtgtOldPassword.length > 0) count++; // KRBTGT password rotation
                    if (this.unprotectedPrivilegedUsers.length > 0) count++; // Protected Users group
                    if (this.machineAccountQuota > 0) count++; // Machine Account Quota
                    return count;
                }},
                
                criticalFindings() {{
                    let findings = [];
                    
                    // ESC vulnerabilities (CRITICAL only)
                    findings.push(...this.certTemplates.filter(t => t['Risk Level'] === 'CRITICAL'));
                    
                    // Kerberoastable accounts
                    findings.push(...this.kerberoastable);
                    
                    // ASREPRoastable accounts
                    findings.push(...this.asreproastable);
                    
                    // Passwords in descriptions
                    findings.push(...this.usersWithPasswordsInInfo);
                    
                    return findings;
                }},
                
                filteredUsers() {{
                    let filtered = [...this.users];
                    
                    // Apply search
                    if (this.userSearch) {{
                        const search = this.userSearch.toLowerCase();
                        filtered = filtered.filter(u => 
                            (u.SAMAccountName && u.SAMAccountName.toLowerCase().includes(search)) ||
                            (u.Name && u.Name.toLowerCase().includes(search))
                        );
                    }}
                    
                    // Apply filter
                    switch (this.userFilter) {{
                        case 'enabled':
                            filtered = filtered.filter(u => u.Enabled === 'True' || u.Enabled === 'TRUE');
                            break;
                        case 'disabled':
                            filtered = filtered.filter(u => u.Enabled === 'False' || u.Enabled === 'FALSE' || !u.Enabled);
                            break;
                        case 'never_expires':
                            filtered = filtered.filter(u => u.PasswordNeverExpires === 'True' || u.PasswordNeverExpires === 'TRUE' || u['Password Never Expires'] === 'True' || u['Password Never Expires'] === 'TRUE');
                            break;
                        case 'must_change':
                            filtered = filtered.filter(u => u.PasswordExpired === 'True' || u.PasswordExpired === 'TRUE' || u['Must Change Password at Logon'] === 'True' || u['Must Change Password at Logon'] === 'TRUE');
                            break;
                        case 'privileged':
                            filtered = filtered.filter(u => u.AdminCount === '1');
                            break;
                        case 'dormant':
                            filtered = filtered.filter(u => {{
                                const age = parseInt(u['Logon Age (days)']);
                                return !isNaN(age) && age > 90;
                            }});
                            break;
                        case 'cannot_change':
                            filtered = filtered.filter(u => u['Cannot Change Password'] === 'True' || u['Cannot Change Password'] === 'TRUE');
                            break;
                        case 'never_logged':
                            filtered = filtered.filter(u => u['Never Logged in'] === 'True' || u['Never Logged in'] === 'TRUE');
                            break;
                    }}
                    
                    // Apply sorting
                    if (this.userSortColumn) {{
                        const direction = this.userSortDirection === 'asc' ? 1 : -1;
                        const column = this.userSortColumn;
                        
                        filtered.sort((a, b) => {{
                            // Special handling for Password Age (numeric)
                            if (column === 'Password Age (days)' || column === 'Logon Age (days)') {{
                                const aValue = parseInt(a[column]) || 0;
                                const bValue = parseInt(b[column]) || 0;
                                return (aValue - bValue) * direction;
                            }}
                            
                            // Special handling for UserName (SAMAccountName)
                            if (column === 'SAMAccountName') {{
                                const aValue = (a.SAMAccountName || a.UserName || '').toLowerCase();
                                const bValue = (b.SAMAccountName || b.UserName || '').toLowerCase();
                                if (aValue < bValue) return -1 * direction;
                                if (aValue > bValue) return 1 * direction;
                                return 0;
                            }}
                            
                            // Normal string comparison
                            const aValue = (a[column] || '').toString().toLowerCase();
                            const bValue = (b[column] || '').toString().toLowerCase();
                            
                            if (aValue < bValue) return -1 * direction;
                            if (aValue > bValue) return 1 * direction;
                            return 0;
                        }});
                    }}
                    
                    return filtered;
                }},
                
                
                paginatedUsers() {{
                    const start = (this.userPage - 1) * this.itemsPerPage;
                    const end = start + this.itemsPerPage;
                    return this.filteredUsers.slice(start, end);
                }},
                
                paginatedComputers() {{
                    const start = (this.computerPage - 1) * this.itemsPerPage;
                    const end = start + this.itemsPerPage;
                    return this.filteredComputers.slice(start, end);
                }},
                
                filteredCertTemplates() {{
                    let filtered = this.certTemplates;
                    
                    // Apply vulnerability filter
                    if (this.certTemplateFilter === 'vulnerable') {{
                        filtered = filtered.filter(t => t['ESC Vulnerabilities'] && t['ESC Vulnerabilities'] !== 'None' && t['ESC Vulnerabilities'].trim() !== '');
                    }} else if (this.certTemplateFilter === 'non-vulnerable') {{
                        filtered = filtered.filter(t => !t['ESC Vulnerabilities'] || t['ESC Vulnerabilities'] === 'None' || t['ESC Vulnerabilities'].trim() === '');
                    }}
                    
                    // Apply risk level filter (case-insensitive)
                    if (this.certTemplateRiskFilter === 'risk-gt-none') {{
                        filtered = filtered.filter(t => {{
                            const riskLevel = (t['Risk Level'] || '').toUpperCase();
                            return riskLevel !== '' && riskLevel !== 'NONE';
                        }});
                    }} else if (this.certTemplateRiskFilter !== 'all') {{
                        filtered = filtered.filter(t => {{
                            const riskLevel = (t['Risk Level'] || '').toUpperCase();
                            return riskLevel === this.certTemplateRiskFilter;
                        }});
                    }}
                    
                    // Apply sorting
                    if (this.certTemplateSortColumn) {{
                        const direction = this.certTemplateSortDirection === 'asc' ? 1 : -1;
                        const column = this.certTemplateSortColumn;
                        
                        filtered.sort((a, b) => {{
                            // Special handling for Risk Level
                            if (column === 'Risk Level') {{
                                const riskPriority = {{
                                    'CRITICAL': 0,
                                    'HIGH': 1,
                                    'MEDIUM': 2,
                                    'Medium': 2,
                                    'LOW': 3,
                                    'Low': 3,
                                    'None': 4
                                }};
                                const aPriority = riskPriority[a[column]] ?? 999;
                                const bPriority = riskPriority[b[column]] ?? 999;
                                return (aPriority - bPriority) * direction;
                            }}
                            
                            // Normal string comparison
                            const aValue = (a[column] || '').toString().toLowerCase();
                            const bValue = (b[column] || '').toString().toLowerCase();
                            
                            if (aValue < bValue) return -1 * direction;
                            if (aValue > bValue) return 1 * direction;
                            return 0;
                        }});
                    }}
                    
                    return filtered;
                }},
                
                paginatedCertTemplates() {{
                    const start = (this.certTemplatePage - 1) * this.itemsPerPage;
                    const end = start + this.itemsPerPage;
                    return this.filteredCertTemplates.slice(start, end);
                }},
                
                paginatedKerberoast() {{
                    let filtered = this.kerberoastable;
                    
                    // Apply sorting
                    if (this.kerberoastSortColumn) {{
                        const direction = this.kerberoastSortDirection === 'asc' ? 1 : -1;
                        const column = this.kerberoastSortColumn;
                        
                        filtered = [...filtered].sort((a, b) => {{
                            // Special handling for Password Age (numeric)
                            if (column === 'Password Age (days)') {{
                                const aValue = parseInt(a[column]) || 0;
                                const bValue = parseInt(b[column]) || 0;
                                return (aValue - bValue) * direction;
                            }}
                            
                            // Special handling for User (SAM Account Name)
                            if (column === 'SAM Account Name') {{
                                const aValue = (a['SAM Account Name'] || '').toLowerCase();
                                const bValue = (b['SAM Account Name'] || '').toLowerCase();
                                if (aValue < bValue) return -1 * direction;
                                if (aValue > bValue) return 1 * direction;
                                return 0;
                            }}
                            
                            // Normal string comparison
                            const aValue = (a[column] || '').toString().toLowerCase();
                            const bValue = (b[column] || '').toString().toLowerCase();
                            
                            if (aValue < bValue) return -1 * direction;
                            if (aValue > bValue) return 1 * direction;
                            return 0;
                        }});
                    }}
                    
                    const start = (this.kerberoastPage - 1) * this.itemsPerPage;
                    const end = start + this.itemsPerPage;
                    return filtered.slice(start, end);
                }},
                
                paginatedAsrep() {{
                    let filtered = this.asreproastable;
                    
                    // Apply sorting
                    if (this.asrepSortColumn) {{
                        const direction = this.asrepSortDirection === 'asc' ? 1 : -1;
                        const column = this.asrepSortColumn;
                        
                        filtered = [...filtered].sort((a, b) => {{
                            // Special handling for Password Age (numeric)
                            if (column === 'Password Age (days)') {{
                                const aValue = parseInt(a[column]) || 0;
                                const bValue = parseInt(b[column]) || 0;
                                return (aValue - bValue) * direction;
                            }}
                            
                            // Special handling for User (SAM Account Name)
                            if (column === 'SAM Account Name') {{
                                const aValue = (a['SAM Account Name'] || '').toLowerCase();
                                const bValue = (b['SAM Account Name'] || '').toLowerCase();
                                if (aValue < bValue) return -1 * direction;
                                if (aValue > bValue) return 1 * direction;
                                return 0;
                            }}
                            
                            // Normal string comparison
                            const aValue = (a[column] || '').toString().toLowerCase();
                            const bValue = (b[column] || '').toString().toLowerCase();
                            
                            if (aValue < bValue) return -1 * direction;
                            if (aValue > bValue) return 1 * direction;
                            return 0;
                        }});
                    }}
                    
                    const start = (this.asrepPage - 1) * this.itemsPerPage;
                    const end = start + this.itemsPerPage;
                    return filtered.slice(start, end);
                }},
                
                paginatedLaps() {{
                    let filtered = this.lapsReadable;
                    
                    // Apply sorting
                    if (this.lapsSortColumn) {{
                        const direction = this.lapsSortDirection === 'asc' ? 1 : -1;
                        const column = this.lapsSortColumn;
                        
                        filtered = [...filtered].sort((a, b) => {{
                            // Normal string comparison
                            const aValue = (a[column] || '').toString().toLowerCase();
                            const bValue = (b[column] || '').toString().toLowerCase();
                            
                            if (aValue < bValue) return -1 * direction;
                            if (aValue > bValue) return 1 * direction;
                            return 0;
                        }});
                    }}
                    
                    const start = (this.lapsPage - 1) * this.itemsPerPage;
                    const end = start + this.itemsPerPage;
                    return filtered.slice(start, end);
                }},
                
                filteredComputers() {{
                    let filtered = [...this.computers];
                    
                    // Apply search
                    if (this.computerSearch) {{
                        const search = this.computerSearch.toLowerCase();
                        filtered = filtered.filter(c => 
                            (c.Name && c.Name.toLowerCase().includes(search)) ||
                            (c.DNSHostName && c.DNSHostName.toLowerCase().includes(search)) ||
                            (c.IPv4Address && c.IPv4Address.toLowerCase().includes(search)) ||
                            (c['Operating System'] && c['Operating System'].toLowerCase().includes(search))
                        );
                    }}
                    
                    // Apply filter
                    switch (this.computerFilter) {{
                        case 'enabled':
                            filtered = filtered.filter(c => c.Enabled === 'True' || c.Enabled === 'TRUE');
                            break;
                        case 'disabled':
                            filtered = filtered.filter(c => c.Enabled === 'False' || c.Enabled === 'FALSE' || !c.Enabled);
                            break;
                        case 'servers':
                            filtered = filtered.filter(c => c['Operating System'] && c['Operating System'].toLowerCase().includes('server'));
                            break;
                        case 'workstations':
                            filtered = filtered.filter(c => c['Operating System'] && !c['Operating System'].toLowerCase().includes('server') && c['Operating System'] !== '');
                            break;
                        case 'dormant':
                            filtered = filtered.filter(c => {{
                                const logonAge = parseInt(c['Logon Age (days)']);
                                return !isNaN(logonAge) && logonAge > 90;
                            }});
                            break;
                        case 'old_password':
                            filtered = filtered.filter(c => {{
                                const pwdAge = parseInt(c['Password Age (days)']);
                                return !isNaN(pwdAge) && pwdAge > 180;
                            }});
                            break;
                        case 'delegated':
                            filtered = filtered.filter(c => c['Delegation Type'] && c['Delegation Type'] !== '' && c['Delegation Type'] !== 'None');
                            break;
                    }}
                    
                    // Apply sorting
                    if (this.computerSortColumn) {{
                        const direction = this.computerSortDirection === 'asc' ? 1 : -1;
                        const column = this.computerSortColumn;
                        
                        filtered.sort((a, b) => {{
                            // Special handling for Password Age and Logon Age (numeric)
                            if (column === 'Password Age (days)' || column === 'Logon Age (days)') {{
                                const aValue = parseInt(a[column]) || 0;
                                const bValue = parseInt(b[column]) || 0;
                                return (aValue - bValue) * direction;
                            }}
                            
                            // Normal string comparison
                            const aValue = (a[column] || '').toString().toLowerCase();
                            const bValue = (b[column] || '').toString().toLowerCase();
                            
                            if (aValue < bValue) return -1 * direction;
                            if (aValue > bValue) return 1 * direction;
                            return 0;
                        }});
                    }}
                    
                    return filtered;
                }}
            }},
            methods: {{
                navigateToSection(tab, sectionId) {{
                    this.activeTab = tab;
                    this.$nextTick(() => {{
                        const element = document.getElementById(sectionId);
                        if (element) {{
                            // Get the element's position
                            const elementPosition = element.getBoundingClientRect().top + window.pageYOffset;
                            // Account for sticky header and navigation (approximately 140px combined)
                            const offset = 140;
                            const scrollToPosition = elementPosition - offset;
                            
                            // Smooth scroll to the adjusted position
                            window.scrollTo({{
                                top: scrollToPosition,
                                behavior: 'smooth'
                            }});
                        }}
                    }});
                }},
                getRiskBorderClass(risk) {{
                    const riskLower = (risk || '').toLowerCase();
                    return {{
                        'border-red-500 bg-red-50 dark:bg-red-900/10': riskLower === 'critical',
                        'border-orange-500 bg-orange-50 dark:bg-orange-900/10': riskLower === 'high',
                        'border-yellow-500 bg-yellow-50 dark:bg-yellow-900/10': riskLower === 'medium',
                        'border-gray-300 bg-gray-50 dark:bg-gray-800': riskLower === 'low' || riskLower === 'none'
                    }};
                }},
                
                getRiskLevel(item) {{
                    // Determine risk for kerberoastable users
                    const pwdAge = parseInt(item['Password Age (days)']);
                    if (pwdAge > 365) return 'HIGH';
                    if (pwdAge > 180) return 'MEDIUM';
                    return 'LOW';
                }},
                
                checkCISCompliance(policy) {{
                    if (!policy || !policy['CIS Benchmark 2024-25'] || policy['CIS Benchmark 2024-25'] === 'N/A' || policy['CIS Benchmark 2024-25'] === '-') {{
                        return 'neutral'; // No CIS benchmark defined
                    }}
                    
                    const currentValue = policy['Current Value'];
                    const cisValue = policy['CIS Benchmark 2024-25'];
                    const policyName = policy.Policy || '';
                    
                    // Enforce password history
                    if (policyName.includes('Enforce password history')) {{
                        const current = parseInt(currentValue);
                        return current >= 24 ? 'pass' : 'fail';
                    }}
                    
                    // Maximum password age
                    if (policyName.includes('Maximum password age')) {{
                        const current = parseInt(currentValue);
                        return (current >= 1 && current <= 365) ? 'pass' : 'fail';
                    }}
                    
                    // Minimum password age
                    if (policyName.includes('Minimum password age')) {{
                        const current = parseInt(currentValue);
                        return current >= 1 ? 'pass' : 'fail';
                    }}
                    
                    // Minimum password length
                    if (policyName.includes('Minimum password length')) {{
                        const current = parseInt(currentValue);
                        return current >= 14 ? 'pass' : 'fail';
                    }}
                    
                    // Password complexity
                    if (policyName.includes('complexity')) {{
                        return currentValue === 'TRUE' ? 'pass' : 'fail';
                    }}
                    
                    // Store password using reversible encryption
                    if (policyName.includes('reversible encryption')) {{
                        return currentValue === 'FALSE' ? 'pass' : 'fail';
                    }}
                    
                    // Account lockout duration
                    if (policyName.includes('Account lockout duration')) {{
                        const current = parseInt(currentValue);
                        return current >= 15 ? 'pass' : 'fail';
                    }}
                    
                    // Account lockout threshold
                    if (policyName.includes('Account lockout threshold')) {{
                        const current = parseInt(currentValue);
                        return (current >= 1 && current <= 5) ? 'pass' : 'fail';
                    }}
                    
                    // Reset account lockout counter
                    if (policyName.includes('Reset account lockout counter')) {{
                        const current = parseInt(currentValue);
                        return current >= 15 ? 'pass' : 'fail';
                    }}
                    
                    return 'neutral';
                }},
                
                getCISComplianceClass(policy) {{
                    const compliance = this.checkCISCompliance(policy);
                    if (compliance === 'pass') {{
                        return 'bg-green-50 dark:bg-green-900/20 border-green-300 dark:border-green-700';
                    }} else if (compliance === 'fail') {{
                        return 'bg-red-50 dark:bg-red-900/20 border-red-300 dark:border-red-700';
                    }}
                    return 'bg-gray-50 dark:bg-gray-800 border-gray-200 dark:border-gray-700';
                }},
                
                sortUsers(column) {{
                    if (this.userSortColumn === column) {{
                        this.userSortDirection = this.userSortDirection === 'asc' ? 'desc' : 'asc';
                    }} else {{
                        this.userSortColumn = column;
                        this.userSortDirection = 'asc';
                    }}
                    this.userPage = 1;
                }},
                
                sortComputers(column) {{
                    if (this.computerSortColumn === column) {{
                        this.computerSortDirection = this.computerSortDirection === 'asc' ? 'desc' : 'asc';
                    }} else {{
                        this.computerSortColumn = column;
                        this.computerSortDirection = 'asc';
                    }}
                    this.computerPage = 1;
                }},
                
                sortVulnCertTemplates(column) {{
                    if (this.vulnCertTemplateSortColumn === column) {{
                        this.vulnCertTemplateSortDirection = this.vulnCertTemplateSortDirection === 'asc' ? 'desc' : 'asc';
                    }} else {{
                        this.vulnCertTemplateSortColumn = column;
                        this.vulnCertTemplateSortDirection = 'asc';
                    }}
                }},
                
                sortKerberoast(column) {{
                    if (this.kerberoastSortColumn === column) {{
                        this.kerberoastSortDirection = this.kerberoastSortDirection === 'asc' ? 'desc' : 'asc';
                    }} else {{
                        this.kerberoastSortColumn = column;
                        this.kerberoastSortDirection = 'asc';
                    }}
                    this.kerberoastPage = 1;
                }},
                
                sortAsrep(column) {{
                    if (this.asrepSortColumn === column) {{
                        this.asrepSortDirection = this.asrepSortDirection === 'asc' ? 'desc' : 'asc';
                    }} else {{
                        this.asrepSortColumn = column;
                        this.asrepSortDirection = 'asc';
                    }}
                    this.asrepPage = 1;
                }},
                
                sortCleartext(column) {{
                    if (this.cleartextSortColumn === column) {{
                        this.cleartextSortDirection = this.cleartextSortDirection === 'asc' ? 'desc' : 'asc';
                    }} else {{
                        this.cleartextSortColumn = column;
                        this.cleartextSortDirection = 'asc';
                    }}
                }},
                
                sortLaps(column) {{
                    if (this.lapsSortColumn === column) {{
                        this.lapsSortDirection = this.lapsSortDirection === 'asc' ? 'desc' : 'asc';
                    }} else {{
                        this.lapsSortColumn = column;
                        this.lapsSortDirection = 'asc';
                    }}
                    this.lapsPage = 1;
                }},
                
                initCharts() {{
                    // User Status Chart - Comprehensive Overview
                    const userStatusCtx = document.getElementById('userStatusChart');
                    if (userStatusCtx) {{
                        new Chart(userStatusCtx, {{
                            type: 'bar',
                            data: {{
                                labels: [
                                    'Enabled', 
                                    'Disabled', 
                                    'Privileged', 
                                    'Dormant', 
                                    'Never Logged In',
                                    'Pwd Never Expires', 
                                    'Must Change Pwd',
                                    'Cannot Change Pwd'
                                ],
                                datasets: [{{
                                    label: 'User Accounts',
                                    data: [
                                        this.enabledUsers.length,
                                        this.users.length - this.enabledUsers.length,
                                        this.privilegedUsers.length,
                                        this.dormantUsers.length,
                                        this.neverLoggedIn.length,
                                        this.passwordNeverExpires.length,
                                        this.mustChangePassword.length,
                                        this.cannotChangePassword.length
                                    ],
                                    backgroundColor: [
                                        '#10b981', // Enabled - green
                                        '#6b7280', // Disabled - gray
                                        '#f59e0b', // Privileged - amber
                                        '#8b5cf6', // Dormant - purple
                                        '#06b6d4', // Never Logged In - cyan
                                        '#fbbf24', // Pwd Never Expires - yellow
                                        '#ef4444', // Must Change Pwd - red
                                        '#ec4899'  // Cannot Change Pwd - pink
                                    ]
                                }}]
                            }},
                            options: {{
                                responsive: true,
                                maintainAspectRatio: true,
                                indexAxis: 'y',
                                onClick: (event, activeElements) => {{
                                    if (activeElements.length > 0) {{
                                        const index = activeElements[0].index;
                                        const filterMap = ['enabled', 'disabled', 'privileged', 'dormant', 'never_logged', 'never_expires', 'must_change', 'cannot_change'];
                                        this.activeTab = 'users';
                                        this.userFilter = filterMap[index];
                                    }}
                                }},
                                plugins: {{
                                    legend: {{
                                        display: false
                                    }},
                                    tooltip: {{
                                        callbacks: {{
                                            label: function(context) {{
                                                const total = csvData.Users.length;
                                                const value = context.parsed.x;
                                                const percentage = ((value / total) * 100).toFixed(1);
                                                return value + ' users (' + percentage + '%)';
                                            }}
                                        }}
                                    }}
                                }},
                                scales: {{
                                    x: {{
                                        type: 'logarithmic',
                                        min: 1,
                                        ticks: {{
                                            precision: 0,
                                            callback: function(value, index, values) {{
                                                // Show major ticks: 1, 10, 100, 1000, etc.
                                                if (value === 1 || value === 10 || value === 100 || value === 1000 || value === 10000) {{
                                                    return value;
                                                }}
                                                return null;
                                            }}
                                        }}
                                    }}
                                }}
                            }}
                        }});
                    }}
                }},
                
                sortCertTemplates(column) {{
                    // Toggle sort direction if same column, otherwise set to ascending
                    if (this.certTemplateSortColumn === column) {{
                        this.certTemplateSortDirection = this.certTemplateSortDirection === 'asc' ? 'desc' : 'asc';
                    }} else {{
                        this.certTemplateSortColumn = column;
                        this.certTemplateSortDirection = 'asc';
                    }}
                    // Reset to first page when sorting
                    this.certTemplatePage = 1;
                }},
                
                sortCertTemplatesByRisk() {{
                    // Use the new sorting mechanism
                    this.certTemplateSortColumn = 'Risk Level';
                    this.certTemplateSortDirection = 'asc';
                    this.certTemplatePage = 1;
                }},
                
                initTrustGraph() {{
                    if (this.trusts.length === 0) return;
                    
                    const container = document.getElementById('trustGraph');
                    if (!container) return;
                    
                    // Get source domain name from Domain data
                    const sourceDomainName = this.domain.length > 0 && this.domain.find(d => d.Category === 'Name') 
                        ? this.domain.find(d => d.Category === 'Name').Value.toLowerCase() 
                        : null;
                    
                    // Helper function to extract domain from Distinguished Name
                    const extractDomain = (dn) => {{
                        if (!dn) return 'Unknown';
                        const dcParts = dn.match(/DC=([^,]+)/g);
                        if (dcParts && dcParts.length > 0) {{
                            return dcParts.map(dc => dc.replace('DC=', '')).join('.').toLowerCase();
                        }}
                        return 'Unknown';
                    }};
                    
                    // Calculate user/computer counts per domain
                    const domainStats = {{}};
                    this.users.forEach(u => {{
                        const domain = extractDomain(u['Distinguished Name'] || u.DistinguishedName);
                        if (domain && domain !== 'unknown') {{
                            if (!domainStats[domain]) domainStats[domain] = {{ users: 0, computers: 0 }};
                            domainStats[domain].users++;
                        }}
                    }});
                    this.computers.forEach(c => {{
                        const domain = extractDomain(c['Distinguished Name'] || c.DistinguishedName);
                        if (domain && domain !== 'unknown') {{
                            if (!domainStats[domain]) domainStats[domain] = {{ users: 0, computers: 0 }};
                            domainStats[domain].computers++;
                        }}
                    }});
                    
                    // Build nodes and edges (filter out domains with no data)
                    const nodes = [];
                    const edges = [];
                    const nodeSet = new Set();
                    const domainNodes = new Set();
                    
                    this.trusts.forEach((trust, idx) => {{
                        const source = trust['Source Domain'] || 'Unknown';
                        const target = trust['Target Domain'] || 'Unknown';
                        
                        if (!nodeSet.has(source)) {{
                            nodeSet.add(source);
                            domainNodes.add(source);
                            const isSourceDomain = sourceDomainName && source.toLowerCase() === sourceDomainName;
                            nodes.push({{
                                id: source,
                                label: source,
                                shape: 'box',
                                color: {{ background: '#3b82f6', border: '#1e40af' }},
                                font: {{ color: '#ffffff', size: 14, bold: true }},
                                margin: 10,
                                size: 30
                            }});
                        }}
                        
                        if (!nodeSet.has(target)) {{
                            nodeSet.add(target);
                            domainNodes.add(target);
                            const isSourceDomain = sourceDomainName && target.toLowerCase() === sourceDomainName;
                            nodes.push({{
                                id: target,
                                label: target,
                                shape: 'box',
                                color: {{ background: isSourceDomain ? '#3b82f6' : '#10b981', border: isSourceDomain ? '#1e40af' : '#047857' }},
                                font: {{ color: '#ffffff', size: 14, bold: true }},
                                margin: 10,
                                size: 30
                            }});
                        }}
                        
                        {{
                            edges.push({{
                                from: source,
                                to: target,
                                arrows: 'to',
                                label: trust['Trust Direction'],
                                font: {{ align: 'middle' }},
                                width: 2
                            }});
                        }}
                    }});
                    
                    // Add user and computer count nodes only for the source domain
                    domainNodes.forEach(domain => {{
                        const isSourceDomain = sourceDomainName && domain.toLowerCase() === sourceDomainName;
                        if (!isSourceDomain) return; // Skip non-source domains
                        
                        const stats = domainStats[domain.toLowerCase()] || {{ users: 0, computers: 0 }};
                        
                        // Add user count node
                        const userNodeId = `${{domain}}_users`;
                        nodes.push({{
                            id: userNodeId,
                            label: `Users\\n${{stats.users}}`,
                            shape: 'circle',
                            color: {{ background: '#8b5cf6', border: '#6d28d9' }},
                            font: {{ color: '#ffffff', size: 12 }},
                            size: 25
                        }});
                        edges.push({{
                            from: domain,
                            to: userNodeId,
                            arrows: 'to',
                            dashes: true,
                            color: {{ color: '#8b5cf6' }},
                            width: 1
                        }});
                        
                        // Add computer count node
                        const computerNodeId = `${{domain}}_computers`;
                        nodes.push({{
                            id: computerNodeId,
                            label: `Computers\\n${{stats.computers}}`,
                            shape: 'circle',
                            color: {{ background: '#f59e0b', border: '#d97706' }},
                            font: {{ color: '#ffffff', size: 12 }},
                            size: 25
                        }});
                        edges.push({{
                            from: domain,
                            to: computerNodeId,
                            arrows: 'to',
                            dashes: true,
                            color: {{ color: '#f59e0b' }},
                            width: 1
                        }});
                    }});
                    
                    const data = {{ nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) }};
                    const options = {{
                        physics: {{
                            enabled: true,
                            barnesHut: {{
                                gravitationalConstant: -10000,
                                springLength: 250,
                                avoidOverlap: 0.5
                            }},
                            stabilization: {{
                                iterations: 200
                            }}
                        }},
                        interaction: {{
                            hover: false,
                            tooltipDelay: 0
                        }},
                        edges: {{
                            smooth: {{
                                type: 'continuous'
                            }}
                        }}
                    }};
                    
                    const network = new vis.Network(container, data, options);
                    
                    network.on('click', (params) => {{
                        if (params.nodes.length > 0) {{
                            const domain = params.nodes[0];
                            console.log('Clicked domain:', domain);
                        }}
                    }});
                }}
            }},
            mounted() {{
                // Set dark mode on body immediately
                document.body.classList.add('dark');
                
                this.$nextTick(() => {{
                    this.initCharts();
                    this.initTrustGraph();
                    this.sortCertTemplatesByRisk();
                    
                    // Update tab counts
                    this.tabs.find(t => t.id === 'findings').count = this.criticalFindings.length;
                }});
            }},
            watch: {{
                activeTab(newTab, oldTab) {{
                    // Reinitialize charts when switching to overview tab
                    if (newTab === 'overview') {{
                        this.$nextTick(() => {{
                            this.initCharts();
                            this.initTrustGraph();
                        }});
                    }}
                }}
            }}
        }}).mount('#app');
        
            // Verify Vue initialized correctly
            setTimeout(() => {{
                const appElement = document.getElementById('app');
                if (appElement && appElement.textContent.includes('{{{{')) {{
                    console.error('Vue templating failed - templates not rendered');
                    alert('Dashboard failed to load properly. Please ensure JavaScript is enabled and try refreshing the page.');
                }}
            }}, 2000);
        }} catch (error) {{
            console.error('Failed to initialize dashboard:', error);
            document.getElementById('app').innerHTML = `
                <div class="fixed inset-0 flex items-center justify-center bg-gray-100">
                    <div class="bg-white p-8 rounded-lg shadow-lg max-w-md">
                        <h2 class="text-2xl font-bold text-red-600 mb-4">
                            <i class="fas fa-exclamation-triangle"></i> Dashboard Load Error
                        </h2>
                        <p class="text-gray-700 mb-4">
                            The dashboard failed to initialize. This may be due to:
                        </p>
                        <ul class="list-disc list-inside text-gray-600 mb-4">
                            <li>Blocked JavaScript or CDN resources</li>
                            <li>Browser compatibility issues</li>
                            <li>Corrupted dashboard file</li>
                        </ul>
                        <p class="text-sm text-gray-500">
                            Error: ${{error.message}}
                        </p>
                    </div>
                </div>
            `;
        }}
    </script>
</body>
</html>
"""
        
        # Write to file
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"[INFO] [+] Dashboard generated: {self.output_file}")
        return True


def generate_dashboard(csv_directory: str, output_file: str = None):
    """Generate HTML dashboard from CSV directory."""
    generator = DashboardGenerator(csv_directory, output_file)
    
    if not generator.load_csv_data():
        print("[!] No CSV data found or error loading CSVs")
        return False
    
    return generator.generate_html()


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 dashboard_generator.py <csv_directory> [output_file]")
        sys.exit(1)
    
    csv_dir = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else None
    
    generate_dashboard(csv_dir, output)

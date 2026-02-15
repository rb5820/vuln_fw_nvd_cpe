# -*- coding: utf-8 -*-
{
    'name': 'Vulnerability Framework NVD - CPE Extension',
    'version': '18.0.1.0.0',
    'category': 'RB5820/Security',
    'summary': 'CPE (Common Platform Enumeration) matching and dictionary management for NVD vulnerability data',
    'description': """
        NVD CPE Extension Module
        ========================
        
        This module extends the NVD vulnerability source with comprehensive CPE (Common Platform Enumeration) 
        functionality, providing:
        
        **CPE Dictionary Management:**
        * Automated CPE dictionary synchronization from NIST
        * Local CPE database with search and filtering
        * Version range parsing and normalization
        * CPE naming scheme validation (CPE 2.3)
        
        **Enhanced Vulnerability Matching:**
        * Automatic asset-to-vulnerability linking via CPE matching
        * Confidence scoring for CPE matches
        * Fuzzy matching algorithms for product identification
        * Version range conflict resolution
        
        **Smart Asset Discovery:**
        * CPE suggestion engine for discovered assets
        * Automated software inventory correlation
        * Product name normalization and aliasing
        * Vendor name disambiguation
        
        **Integration Features:**
        * Extends vuln_fw_nvd connector with CPE processing
        * Seamless integration with asset management systems
        * Configurable matching sensitivity and thresholds
        * Background processing for large CPE datasets
        
        **Technical Features:**
        * Nightly CPE dictionary refresh automation
        * Performance-optimized CPE matching algorithms
        * Comprehensive logging and debugging tools
        * RESTful API endpoints for CPE operations
    """,
    'author': 'RB5820',
    'website': 'https://www.attiesatelier.be',
    'depends': [
        'vuln_fw_nvd',
        'base',
        'mail',
        'web'
    ],
    'data': [
        # Security
        'security/security.xml',
        'security/ir.model.access.csv',
        
        # Views (must be loaded before menus)
        'views/vuln_fw_nvd_cpe_dictionary.xml',
        'views/vuln_fw_nvd_cpe_vendor_views.xml',
        'views/vuln_fw_nvd_cpe_product_views.xml',
        'views/vuln_fw_nvd_reference_cpe_views.xml',
        'views/vuln_fw_nvd_cpe_webhook_views.xml',
        'views/vuln_fw_nvd_cpe_webhook_receiver_views.xml',
        'views/vuln_fw_nvd_cpe_receiver_cpe23_views.xml',

        'views/vuln_fw_nvd_cpe_api_connector_views.xml',
        'views/menus.xml',
        
        # Data
        'data/vuln_fw_nvd_cpe_vendor_data.xml',
        'data/ir_cron.xml',
        #'data/demo_connector.xml',
        # Connectors (must be loaded after views to avoid reference issues)
        'data/vuln_fw_nvd_api_connector.xml',
    ],
    'demo': [],
    'installable': True,
    'application': False,
    'auto_install': False,
    'license': 'OPL-1',
}
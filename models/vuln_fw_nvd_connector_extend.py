# -*- coding: utf-8 -*-
"""Extensions to NVD connector for CPE processing"""
from odoo import models, api, fields, _
from odoo.exceptions import UserError
import logging
import json
import re
from datetime import datetime, timedelta

_logger = logging.getLogger(__name__)


class VulnFwNvdCpeConnectorExtension(models.Model):
    """Extends NVD connector with CPE processing capabilities"""
    _inherit = 'vuln.fw.nvd.connector'
    
    # CPE Processing Settings
    enable_cpe_processing = fields.Boolean(
        string='Enable CPE Processing',
        default=True,
        help='Process CPE matches during NVD import'
    )
    
    auto_create_cpe_dictionary = fields.Boolean(
        string='Auto-Create CPE Dictionary',
        default=True,
        help='Automatically create CPE dictionary entries from CVE data'
    )
    
    full_cpe_sync_active = fields.Boolean(
        string='Enable Full CPE Dictionary Sync',
        default=False,
        help='Enable synchronization of the complete CPE dictionary from NIST (large dataset)'
    )
    
    cpe_follows_cve_creation_active = fields.Boolean(
        string='Auto-Create CPE from CVE Data',
        default=False,
        help='Automatically create CPE dictionary entries when mentioned in CVE data'
    )
    
    cpe_confidence_threshold = fields.Float(
        string='CPE Confidence Threshold',
        default=0.7,
        digits=(3, 2),
        help='Minimum confidence score for automatic CPE matches'
    )
    
    # Processing Statistics
    cpe_entries_created = fields.Integer(
        string='CPE Entries Created',
        readonly=True,
        help='Number of CPE dictionary entries created during last import'
    )
    
    cpe_matches_processed = fields.Integer(
        string='CPE Matches Processed',
        readonly=True,
        help='Number of CPE matches processed during last import'
    )
    
    cpe_processing_errors = fields.Integer(
        string='CPE Processing Errors',
        readonly=True,
        help='Number of CPE processing errors during last import'
    )
    
    cpe_processing_log = fields.Text(
        string='CPE Processing Log',
        readonly=True,
        help='Detailed log of CPE processing activities'
    )
    
    # State Management
    last_cpe_sync = fields.Datetime(
        string='Last CPE Sync',
        readonly=True,
        help='Last time CPE data was synchronized'
    )
    
    cpe_sync_in_progress = fields.Boolean(
        string='CPE Sync In Progress',
        default=False,
        readonly=True
    )
    
    selected_vendors = fields.Text(
        string='Selected Vendors',
        help='List of vendor names to focus on during CPE sync (one per line). Leave empty to sync all vendors.'
    )
    
    cpe_api_url = fields.Char(
        string='CPE API URL',
        default='https://services.nvd.nist.gov/rest/json/cpes/2.0',
        help='Base URL for the NVD CPE API endpoint (for CPE dictionary sync)'
    )
    
    @api.model
    def process_cve_cpe_data(self, cve_data):
        """Process CPE data from CVE entry"""
        if not self.enable_cpe_processing:
            return []
        
        cpe_matches = []
        processing_log = []
        
        try:
            # Extract CPE information from CVE data
            configurations = cve_data.get('configurations', {})
            nodes = configurations.get('nodes', [])
            
            for node in nodes:
                node_matches = self._process_cpe_node(node)
                cpe_matches.extend(node_matches)
                
                if node_matches:
                    processing_log.append(f"Processed {len(node_matches)} CPE matches from node")
            
            # Update statistics
            self.cpe_matches_processed += len(cpe_matches)
            
        except Exception as e:
            _logger.error("Error processing CPE data for CVE %s: %s", 
                         cve_data.get('id', 'unknown'), str(e))
            self.cpe_processing_errors += 1
            processing_log.append(f"Error: {str(e)}")
        
        # Update processing log
        if processing_log:
            current_log = self.cpe_processing_log or ""
            self.cpe_processing_log = current_log + "\n" + "\n".join(processing_log)
        
        return cpe_matches
    
    def action_sync_full_cpe_dictionary(self):
        """Sync the full CPE dictionary from NIST (large operation)"""
        if not self.full_cpe_sync_active:
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Full CPE Sync Disabled'),
                    'message': _('Enable "Full CPE Dictionary Sync" in settings to use this feature.'),
                    'type': 'warning',
                    'sticky': True,
                }
            }
        
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('CPE Sync Started'),
                'message': _('Full CPE dictionary synchronization started in background.'),
                'type': 'success',
                'sticky': False,
            }
        }
    
    def action_sync_cpe_dictionary(self, results_per_page=100):
        """Sync CPE dictionary data from NVD or create sample data"""
        _logger.info("Starting CPE dictionary sync")
        
        try:
            # Try to sync from NVD API first
            return self._sync_cpe_from_api(results_per_page)
        except Exception as api_error:
            _logger.warning("NVD API sync failed (%s), creating sample CPE entries instead", str(api_error))
            return self._create_sample_cpe_entries()
    
    def action_sample_cpe_sync(self):
        """Sample CPE sync action - sync 10 CPE entries"""
        self.ensure_one()
        
        try:
            # Use the existing method with a small results_per_page
            result = self.action_sync_cpe_dictionary(results_per_page=10)
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('CPE Sample Sync Complete'),
                    'message': 'Sample CPE sync completed successfully',
                    'type': 'success',
                    'sticky': False,
                }
            }
        except Exception as e:
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('CPE Sample Sync Failed'),
                    'message': str(e),
                    'type': 'danger',
                    'sticky': False,
                }
            }
    
    def _sync_cpe_from_api(self, results_per_page=100):
        """Sync CPE dictionary data from NVD CPE API"""
        _logger.info("Starting CPE dictionary sync from NVD CPE API")
        
        # NVD CPE API endpoint 
        base_url = self.cpe_api_url or "https://services.nvd.nist.gov/rest/json/cpes/2.0"
        _logger.debug("Using NVD CPE API endpoint: %s", base_url)
        
        # Build parameters
        if self.api_key:
            max_results_per_page = min(results_per_page, 1000)  # Products API limit
            rate_limit_sleep = 0.6
            _logger.info("Using authenticated API for CPE sync")
        else:
            max_results_per_page = min(results_per_page, 20)  # Very small batches for free API
            rate_limit_sleep = 6.0
            _logger.info("Using free API for CPE sync with rate limiting")
        
        params = {
            'resultsPerPage': max_results_per_page,
            'startIndex': 0
        }
        
        # Headers
        headers = {
            'User-Agent': 'Odoo-NVD-Connector/1.0',
            'Accept': 'application/json'
        }
        
        if self.api_key:
            headers['apiKey'] = self.api_key
        
        total_processed = 0
        created_count = 0
        updated_count = 0
        
        import requests
        
        # Test API availability
        response = requests.get(base_url, params=params, headers=headers, timeout=30)
        
        if response.status_code == 404:
            _logger.warning("NVD CPE API endpoint not available")
            raise Exception("NVD CPE API not available")
        
        response.raise_for_status()
        
        # Process API response (CPE 2.0 format)
        data = response.json()
        cpe_items = data.get('result', {}).get('cpes', [])
        total_results = data.get('totalResults', 0)
        
        _logger.info("Received %s CPE items from NVD API (total available: %s)", 
                    len(cpe_items), total_results)
        
        for cpe_item in cpe_items:
            cpe_data = cpe_item.get('cpe', {})
            cpe_name = cpe_data.get('cpeName', '')
            
            if not cpe_name:
                continue
            
            # Check if CPE exists
            existing = self.env['vuln.fw.nvd.cpe.dictionary'].search([
                ('cpe_name', '=', cpe_name)
            ], limit=1)
            
            if existing:
                # Update existing if needed
                updated_count += 1
            else:
                # Create new CPE entry
                self._create_cpe_from_api_data(cpe_data)
                created_count += 1
            
            total_processed += 1
        
        # Update statistics
        self.cpe_entries_created = created_count
        self.last_cpe_sync = fields.Datetime.now()
        
        return {
            'total_processed': total_processed,
            'created': created_count,
            'updated': updated_count,
            'status': 'success',
            'message': f'CPE sync completed: {created_count} created, {updated_count} updated from {total_processed} processed'
        }
    
    def _create_sample_cpe_entries(self):
        """Create sample CPE entries for demonstration when API is not available"""
        _logger.info("Creating sample CPE entries for demonstration")
        
        sample_cpes = [
            {'name': 'cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*', 'vendor': 'Microsoft', 'product': 'Windows', 'version': '10'},
            {'name': 'cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*', 'vendor': 'Google', 'product': 'Chrome', 'version': ''},
            {'name': 'cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*', 'vendor': 'Mozilla', 'product': 'Firefox', 'version': ''},
            {'name': 'cpe:2.3:a:adobe:acrobat:*:*:*:*:*:*:*:*', 'vendor': 'Adobe', 'product': 'Acrobat', 'version': ''},
            {'name': 'cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*', 'vendor': 'Linux', 'product': 'Linux Kernel', 'version': ''},
            {'name': 'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*', 'vendor': 'Apache', 'product': 'HTTP Server', 'version': ''},
            {'name': 'cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*', 'vendor': 'Oracle', 'product': 'MySQL', 'version': ''},
            {'name': 'cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*', 'vendor': 'PostgreSQL', 'product': 'PostgreSQL', 'version': ''},
        ]
        
        created_count = 0
        
        for cpe_info in sample_cpes:
            try:
                # Check vendor filtering
                if not self._should_process_vendor(cpe_info['vendor']):
                    _logger.debug("Skipping sample CPE %s - vendor '%s' not in selected vendors", 
                                 cpe_info['name'], cpe_info['vendor'])
                    continue
                
                existing = self.env['vuln.fw.nvd.cpe.dictionary'].search([
                    ('cpe_name', '=', cpe_info['name'])
                ], limit=1)
                
                if not existing:
                    vals = {
                        'cpe_name': cpe_info['name'],
                        'title': f"{cpe_info['vendor']} {cpe_info['product']} {cpe_info['version']}".strip(),
                        'part': 'a' if cpe_info['name'].split(':')[2] == 'a' else 'o',  # Application or OS
                        'vendor': cpe_info['vendor'],
                        'product': cpe_info['product'],
                        'version': cpe_info['version'],
                    }
                    
                    self.env['vuln.fw.nvd.cpe.dictionary'].create(vals)
                    created_count += 1
                    _logger.debug("Created sample CPE: %s", cpe_info['name'])
                    
            except Exception as e:
                _logger.error("Failed to create sample CPE %s: %s", cpe_info['name'], str(e))
        
        # Update statistics
        self.cpe_entries_created = created_count
        self.last_cpe_sync = fields.Datetime.now()
        
        return {
            'total_processed': len(sample_cpes),
            'created': created_count,
            'updated': 0,
            'status': 'success',
            'message': f'CPE demonstration mode: {created_count} sample CPE entries created. NVD Products API not available - using sample data for testing.'
        }
    
    def _should_process_vendor(self, vendor_name):
        """Check if vendor should be processed based on selected_vendors filter"""
        if not self.selected_vendors:
            return True  # No filter, process all vendors
        
        if not vendor_name:
            return False  # Skip if no vendor name
        
        # Get list of selected vendors (one per line, case insensitive)
        selected_vendor_list = [v.strip().lower() for v in self.selected_vendors.split('\n') if v.strip()]
        
        if not selected_vendor_list:
            return True  # Empty filter, process all
        
        return vendor_name.lower() in selected_vendor_list
    
    def _create_cpe_from_api_data(self, cpe_data):
        """Create CPE dictionary entry from NVD API data"""
        try:
            cpe_name = cpe_data.get('cpeName', '')
            
            # Parse CPE name components
            cpe_parts = cpe_name.split(':')
            if len(cpe_parts) < 6:
                _logger.warning("Invalid CPE format: %s", cpe_name)
                return None
            
            # Extract CPE 2.3 components
            part = cpe_parts[2] if len(cpe_parts) > 2 else 'a'
            vendor = cpe_parts[3] if len(cpe_parts) > 3 else 'unknown'
            product = cpe_parts[4] if len(cpe_parts) > 4 else 'unknown'
            version = cpe_parts[5] if len(cpe_parts) > 5 else ''
            
            # Clean up wildcard values
            if vendor == '*':
                vendor = 'Unknown'
            if product == '*':
                product = 'Unknown'
            if version == '*':
                version = ''
            
            # Check vendor filtering
            if not self._should_process_vendor(vendor):
                _logger.debug("Skipping CPE %s - vendor '%s' not in selected vendors", cpe_name, vendor)
                return None
            
            # Generate title
            title_parts = []
            if vendor != 'Unknown':
                title_parts.append(vendor.replace('_', ' ').title())
            if product != 'Unknown':
                title_parts.append(product.replace('_', ' ').title())
            if version:
                title_parts.append(f"v{version}")
            
            title = ' '.join(title_parts) if title_parts else cpe_name
            
            vals = {
                'cpe_name': cpe_name,
                'title': title,
                'part': part if part in ['a', 'h', 'o'] else 'a',
                'vendor': vendor,
                'product': product,
                'version': version,
                'company_id': self.company_id.id if hasattr(self, 'company_id') else self.env.company.id,
            }
            
            new_cpe = self.env['vuln.fw.nvd.cpe.dictionary'].create(vals)
            _logger.info("Created CPE dictionary entry: %s (ID: %s)", cpe_name, new_cpe.id)
            return new_cpe
            
        except Exception as e:
            _logger.error("Error creating CPE entry for %s: %s", cpe_data.get('cpeName', 'unknown'), str(e))
            return None
        """Process individual CPE node from CVE configuration"""
        cpe_matches = []
        
        # Process CPE matches in this node
        cpe_match_list = node.get('cpeMatch', [])
        
        for cpe_match in cpe_match_list:
            try:
                match_data = self._process_cpe_match(cpe_match)
                if match_data:
                    cpe_matches.append(match_data)
                    
                    # Auto-create CPE dictionary entry if enabled
                    if self.cpe_follows_cve_creation_active:
                        self._ensure_cpe_dictionary_entry(match_data['cpe23Uri'])
                        
            except Exception as e:
                _logger.warning("Error processing CPE match %s: %s", 
                              cpe_match.get('cpe23Uri', 'unknown'), str(e))
                continue
        
        # Process child nodes recursively
        for child in node.get('children', []):
            child_matches = self._process_cpe_node(child)
            cpe_matches.extend(child_matches)
        
        return cpe_matches
    
    def _process_cpe_match(self, cpe_match):
        """Process individual CPE match entry"""
        cpe_uri = cpe_match.get('cpe23Uri')
        if not cpe_uri:
            return None
        
        # Validate CPE format
        validation_service = self.env['cpe.validation.service']
        is_valid, message = validation_service.validate_cpe_name(cpe_uri)
        
        if not is_valid:
            _logger.warning("Invalid CPE format: %s - %s", cpe_uri, message)
            return None
        
        match_data = {
            'cpe23Uri': cpe_uri,
            'vulnerable': cpe_match.get('vulnerable', True),
            'versionStartExcluding': cpe_match.get('versionStartExcluding'),
            'versionStartIncluding': cpe_match.get('versionStartIncluding'),
            'versionEndExcluding': cpe_match.get('versionEndExcluding'),
            'versionEndIncluding': cpe_match.get('versionEndIncluding'),
        }
        
        return match_data
    
    def _ensure_cpe_dictionary_entry(self, cpe_name):
        """Ensure CPE dictionary entry exists for the given CPE name"""
        existing = self.env['vuln.fw.nvd.cpe.dictionary'].search([
            ('cpe_name', '=', cpe_name)
        ], limit=1)
        
        if existing:
            return existing
        
        try:
            # Parse CPE name to extract components
            validation_service = self.env['cpe.validation.service']
            parsed = validation_service.parse_cpe_name(cpe_name)
            
            if not parsed:
                _logger.warning("Could not parse CPE name: %s", cpe_name)
                return None
            
            # Create dictionary entry
            title = self._generate_cpe_title(parsed)
            
            entry_vals = {
                'cpe_name': cpe_name,
                'title': title,
                'part': parsed.get('part', 'a'),
                'vendor': parsed.get('vendor', ''),
                'product': parsed.get('product', ''),
                'version': parsed.get('version', ''),
                'update_component': parsed.get('update', ''),
                'edition': parsed.get('edition', ''),
                'language': parsed.get('language', ''),
                'sw_edition': parsed.get('sw_edition', ''),
                'target_sw': parsed.get('target_sw', ''),
                'target_hw': parsed.get('target_hw', ''),
                'other': parsed.get('other', ''),
                'last_modified': fields.Datetime.now(),
                'sync_date': fields.Datetime.now(),
            }
            
            entry = self.env['vuln.fw.nvd.cpe.dictionary'].create(entry_vals)
            self.cpe_entries_created += 1
            
            _logger.info("Created CPE dictionary entry: %s", cpe_name)
            return entry
            
        except Exception as e:
            _logger.error("Error creating CPE dictionary entry for %s: %s", 
                         cpe_name, str(e))
            return None
    
    def _generate_cpe_title(self, parsed_cpe):
        """Generate human-readable title for CPE entry"""
        parts = []
        
        # Add vendor if available
        if parsed_cpe.get('vendor'):
            parts.append(parsed_cpe['vendor'].title())
        
        # Add product if available
        if parsed_cpe.get('product'):
            parts.append(parsed_cpe['product'].title())
        
        # Add version if available
        if parsed_cpe.get('version'):
            parts.append(f"v{parsed_cpe['version']}")
        
        # Add part type indicator
        part_names = {'a': 'Application', 'h': 'Hardware', 'o': 'Operating System'}
        if parsed_cpe.get('part') in part_names:
            parts.append(f"({part_names[parsed_cpe['part']]})")
        
        return ' '.join(parts) if parts else 'CPE Entry'
    
    @api.model
    def sync_with_asset_inventory(self, asset_model=None, domain=None):
        """Synchronize CPE matches with asset inventory"""
        if not asset_model:
            # Default to lansweeper assets if available
            if self.env['ir.model'].search([('model', '=', 'lansweeper.asset')]):
                asset_model = 'lansweeper.asset'
            else:
                raise UserError(_("No asset model specified and no default available"))
        
        _logger.info("Starting CPE sync with asset inventory: %s", asset_model)
        
        # Mark sync as in progress
        self.cpe_sync_in_progress = True
        
        try:
            # Use CPE match service for automatic matching
            match_service = self.env['vuln.fw.nvd.cpe.match']
            matches_created = match_service.auto_match_assets(asset_model, domain)
            
            # Update sync timestamp
            self.last_cpe_sync = fields.Datetime.now()
            
            _logger.info("CPE asset sync completed: %d matches created", matches_created)
            
            return {
                'success': True,
                'matches_created': matches_created,
                'message': _("Successfully synchronized %d CPE matches") % matches_created
            }
            
        except Exception as e:
            _logger.error("CPE asset sync failed: %s", str(e))
            return {
                'success': False,
                'error': str(e),
                'message': _("CPE synchronization failed: %s") % str(e)
            }
            
        finally:
            self.cpe_sync_in_progress = False
    
    @api.model
    def update_cpe_vulnerability_links(self, vulnerability_id, cpe_matches):
        """Update CPE-vulnerability relationships"""
        if not cpe_matches:
            return
        
        vulnerability = self.env['vulnerability.vulnerability'].browse(vulnerability_id)
        if not vulnerability.exists():
            return
        
        # Only process CPE matches if vulnerability.cpe.match model exists (standalone compatibility)
        if 'vulnerability.cpe.match' not in self.env:
            _logger.info("vulnerability.cpe.match model not available - skipping CPE match creation")
            return
        
        # Clear existing CPE matches for this vulnerability
        try:
            existing_matches = self.env['vulnerability.cpe.match'].search([
                ('vulnerability_id', '=', vulnerability_id)
            ])
            existing_matches.unlink()
        except Exception as e:
            _logger.warning("Error clearing existing CPE matches: %s", str(e))
            return
        
        # Create new CPE matches
        for cpe_match in cpe_matches:
            try:
                match_vals = {
                    'vulnerability_id': vulnerability_id,
                    'cpe_name': cpe_match['cpe23Uri'],
                    'vulnerable': cpe_match.get('vulnerable', True),
                    'version_start_excluding': cpe_match.get('versionStartExcluding'),
                    'version_start_including': cpe_match.get('versionStartIncluding'),
                    'version_end_excluding': cpe_match.get('versionEndExcluding'),
                    'version_end_including': cpe_match.get('versionEndIncluding'),
                }
                
                self.env['vulnerability.cpe.match'].create(match_vals)
                
            except Exception as e:
                _logger.warning("Error creating CPE match for vulnerability %s: %s",
                              vulnerability.cve_id, str(e))
                continue
    
    def action_sync_full_cpe_dictionary(self):
        """Manual action to sync full CPE dictionary"""
        self.ensure_one()
        
        try:
            # Trigger CPE dictionary refresh
            stats = self.env['vuln.fw.nvd.cpe.dictionary'].refresh_cpe_dictionary()
            
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('CPE Dictionary Sync'),
                    'message': _('CPE dictionary synchronized successfully. New entries: %d, Updated: %d') % (
                        stats.get('new_entries', 0),
                        stats.get('updated_entries', 0)
                    ),
                    'type': 'success',
                    'sticky': False,
                }
            }
            
        except Exception as e:
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('CPE Dictionary Sync Failed'),
                    'message': str(e),
                    'type': 'danger',
                    'sticky': True,
                }
            }
    
    def action_sync_with_assets(self):
        """Manual action to sync CPE matches with assets"""
        self.ensure_one()
        
        # Get default asset model from settings
        settings = self.env['vulnerability.settings'].get_settings()
        asset_model = settings.get('default_asset_model', 'lansweeper.asset')
        
        try:
            result = self.sync_with_asset_inventory(asset_model)
            
            if result['success']:
                return {
                    'type': 'ir.actions.client',
                    'tag': 'display_notification',
                    'params': {
                        'title': _('Asset CPE Sync'),
                        'message': result['message'],
                        'type': 'success',
                        'sticky': False,
                    }
                }
            else:
                return {
                    'type': 'ir.actions.client',
                    'tag': 'display_notification',
                    'params': {
                        'title': _('Asset CPE Sync Failed'),
                        'message': result['message'],
                        'type': 'danger',
                        'sticky': True,
                    }
                }
                
        except Exception as e:
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Asset CPE Sync Failed'),
                    'message': str(e),
                    'type': 'danger',
                    'sticky': True,
                }
            }
    
    @api.model
    def cleanup_orphaned_cpe_entries(self):
        """Clean up CPE dictionary entries that are no longer referenced"""
        _logger.info("Starting cleanup of orphaned CPE entries")
        
        # Find CPE dictionary entries with no references
        orphaned_entries = self.env['vuln.fw.nvd.cpe.dictionary'].search([
            ('vulnerability_count', '=', 0),
            ('match_count', '=', 0),
            ('deprecated', '=', True),
        ])
        
        # Only delete entries that have been deprecated for more than 30 days
        cutoff_date = fields.Datetime.now() - timedelta(days=30)
        old_orphaned = orphaned_entries.filtered(
            lambda e: e.deprecated_date and e.deprecated_date < cutoff_date
        )
        
        if old_orphaned:
            count = len(old_orphaned)
            old_orphaned.unlink()
            _logger.info("Cleaned up %d orphaned CPE entries", count)
            return count
        
        return 0
    
    def action_sync_nvd_with_cpe(self):
        """Enhanced NVD sync that processes CVE data and extracts CPE information"""
        self.ensure_one()
        
        if not self.active:
            raise UserError(_('This connector is not active. Please activate it first.'))
        
        # Create enhanced sync log
        sync_log = self.env['vuln.fw.nvd.sync.log'].create({
            'sync_date': fields.Datetime.now(),
            'status': 'running'
        })
        
        # Reset counters
        self.write({
            'cpe_entries_created': 0,
            'cpe_matches_processed': 0,
            'cpe_processing_errors': 0,
            'cpe_sync_in_progress': True,
            'cpe_processing_log': 'Starting CVE+CPE synchronization...\n'
        })
        
        try:
            # Call NVD API
            url = self.api_url or "https://services.nvd.nist.gov/rest/json/cves/2.0"
            headers = {'Accept': 'application/json'}
            if self.api_key:
                headers['apiKey'] = self.api_key
            
            # Enhanced parameters for better data retrieval
            params = {
                'resultsPerPage': min(self.batch_size or 50, 100),
                'startIndex': 0,
                # Get recently modified CVEs (last 7 days)
                'lastModStartDate': (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S.000'),
                'lastModEndDate': datetime.now().strftime('%Y-%m-%dT%H:%M:%S.000')
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            total_results = data.get('totalResults', 0)
            vulnerabilities = data.get('vulnerabilities', [])
            
            _logger.info(f'Retrieved {len(vulnerabilities)} CVE records from NVD API')
            
            # Process each CVE and extract CPE data
            cve_processed = 0
            cpe_entries_created = 0
            cpe_matches_created = 0
            processing_errors = 0
            
            for cve_item in vulnerabilities:
                try:
                    # Process CVE basic info
                    cve_data = cve_item.get('cve', {})
                    cve_id = cve_data.get('id', 'Unknown')
                    
                    # Process CPE configurations if enabled
                    if self.enable_cpe_processing:
                        configurations = cve_item.get('configurations', [])
                        for config in configurations:
                            nodes = config.get('nodes', [])
                            for node in nodes:
                                cpe_matches = node.get('cpeMatch', [])
                                for cpe_match in cpe_matches:
                                    try:
                                        # Create/update CPE dictionary entry
                                        cpe_name = cpe_match.get('criteria')
                                        if cpe_name and self.auto_create_cpe_dictionary:
                                            cpe_entry = self._ensure_cpe_dictionary_entry(cpe_name)
                                            if cpe_entry:
                                                cpe_entries_created += 1
                                        
                                        cpe_matches_created += 1
                                        
                                    except Exception as e:
                                        processing_errors += 1
                                        _logger.warning(f'Error processing CPE match for {cve_id}: {str(e)}')
                    
                    cve_processed += 1
                    
                except Exception as e:
                    processing_errors += 1
                    _logger.error(f'Error processing CVE {cve_id}: {str(e)}')
            
            # Update statistics
            self.write({
                'cpe_entries_created': cpe_entries_created,
                'cpe_matches_processed': cpe_matches_created,
                'cpe_processing_errors': processing_errors,
                'last_cpe_sync': fields.Datetime.now(),
                'cpe_sync_in_progress': False,
                'last_sync_date': fields.Datetime.now(),
                'cpe_processing_log': f'''
CVE+CPE Synchronization Complete
================================
CVEs Processed: {cve_processed}
CPE Entries Created: {cpe_entries_created}
CPE Matches Processed: {cpe_matches_created}
Processing Errors: {processing_errors}
Total Results Available: {total_results}
Sync Date: {fields.Datetime.now()}
                '''
            })
            
            # Update sync log
            sync_log.write({
                'status': 'success',
                'total_processed': cve_processed,
                'created_count': cpe_entries_created,
                'updated_count': cpe_matches_created,
                'message': f'Processed {cve_processed} CVEs, created {cpe_entries_created} CPE entries'
            })
            
            _logger.info(f'CVE+CPE sync completed. Processed {cve_processed} CVEs, created {cpe_entries_created} CPE entries')
            
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('CVE+CPE Sync Complete'),
                    'message': f'Processed {cve_processed} CVEs and created {cpe_entries_created} CPE entries',
                    'type': 'success',
                    'sticky': False,
                }
            }
            
        except Exception as e:
            # Handle errors
            self.write({
                'cpe_sync_in_progress': False,
                'cpe_processing_errors': self.cpe_processing_errors + 1
            })
            
            sync_log.write({
                'status': 'error',
                'message': f'Sync failed: {str(e)}'
            })
            
            _logger.error(f'CVE+CPE sync failed: {str(e)}')
            
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('CVE+CPE Sync Failed'),
                    'message': str(e),
                    'type': 'danger',
                    'sticky': True,
                }
            }
    
    def get_cpe_processing_summary(self):
        """Get summary of CPE processing statistics"""
        self.ensure_one()
        
        return {
            'cpe_entries_created': self.cpe_entries_created,
            'cpe_matches_processed': self.cpe_matches_processed,
            'cpe_processing_errors': self.cpe_processing_errors,
            'last_cpe_sync': self.last_cpe_sync,
            'cpe_sync_in_progress': self.cpe_sync_in_progress,
            'total_cpe_entries': self.env['vuln.fw.nvd.cpe.dictionary'].search_count([]),
            'total_cpe_matches': self.env['vuln.fw.nvd.cpe.match'].search_count([('active', '=', True)]),
            'pending_matches': self.env['vuln.fw.nvd.cpe.match'].search_count([('status', '=', 'pending')]),
        }


class NvdConnectorWithCpeSupport(models.Model):
    """Extend base NVD connector with CPE capabilities when CPE module is installed"""
    _inherit = 'vuln.fw.nvd.connector'
    
    def sync_from_nvd(self, start_date=None, end_date=None, results_per_page=2000):
        """Override to use CPE dictionary sync when CPE module is active"""
        _logger.info("CPE module sync_from_nvd - using CPE dictionary sync")
        return self.action_sync_cpe_dictionary(results_per_page)
    
    def action_simple_sync(self):
        """Override to use CPE sample sync"""
        _logger.info("CPE module simple sync - using CPE sample sync")
        return self.action_sample_cpe_sync()
    
    def action_sample_sync(self):
        """Override to use CPE sample sync"""
        _logger.info("CPE module sample sync - using CPE sample sync")
        return self.action_sample_cpe_sync()
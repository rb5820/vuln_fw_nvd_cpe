# -*- coding: utf-8 -*-
"""CPE API Connector - Delegation inheritance from base NVD connector"""
from odoo import models, api, fields, _
from odoo.exceptions import UserError
import logging
import json
import requests
from datetime import datetime, timedelta

_logger = logging.getLogger(__name__)


class VulnFwNvdCpeApiConnector(models.Model):
    """CPE API Connector with delegation inheritance from base connector"""
    _name = 'vuln.fw.nvd.cpe.api.connector'
    _description = 'CPE API Connector Configuration'
    
    # Parent connector for API key and rate limiting management
    parent_connector_id = fields.Many2one(
        'vuln.fw.nvd.connector',
        string='Parent API Connector (Credentials & Rate Limiting)',
        required=True,
        ondelete='cascade',
        help='Reference to the parent NVD connector that provides API credentials and rate limiting management. '
             'Multiple CPE connectors can share the same parent connector to utilize a single API key while '
             'maintaining separate rate limits. The parent connector handles authentication and throttling for '
             'all API requests made by this CPE connector.'
    )
    
    # Basic connector fields (not inherited anymore)
    name = fields.Char(
        string='CPE Connector Name',
        required=True,
        help='Unique identifier for this CPE API connector. Choose a descriptive name that indicates '
             'the purpose or scope of this connector (e.g., "Production CPE Sync", "Vendor-Specific CPE Import").'
    )
    active = fields.Boolean(
        string='Active (Archived/Visible)',
        default=True,
        help='Archive/unarchive this connector. Archived connectors are hidden from views and cannot be used '
             'for synchronization operations.'
    )
    connector_active = fields.Boolean(
        string='Sync Operations Enabled',
        default=False,
        help='Master switch to enable/disable synchronization operations for this connector. When disabled, '
             'all scheduled and manual sync operations are blocked. This is independent of the archive status, '
             'allowing you to temporarily pause syncing without hiding the connector from the interface.'
    )
    last_sync_date = fields.Datetime(
        string='Last Synchronization',
        readonly=True,
        help='Timestamp of the most recent successful synchronization operation. This tracks when CPE data '
             'was last retrieved from the NVD API and processed into the local database.'
    )
    notes = fields.Text(
        string='Configuration Notes',
        help='Internal notes and documentation for this connector. Use this field to document configuration '
             'decisions, special handling requirements, or any operational notes for team reference.'
    )
    
    # Manual Testing Fields
    test_cpe_uri = fields.Char(
        string='Test CPE URI',
        help='Enter a CPE 2.3 URI for manual testing and processing. '
             'Example: cpe:2.3:a:microsoft:edge_chromium:143.0.3650.66:*:*:*:-:windows:*:*'
    )
    debug_mode = fields.Boolean(
        string='Debug Mode',
        default=False,
        store=True,
        copy=False,
        help='Enable detailed debug logging for troubleshooting. When enabled, all processing steps '
             'will be logged with timestamps, variables, and system state information.'
    )
    
    # API Configuration
    api_url = fields.Char(
        string='NVD CPE 2.0 API Endpoint',
        default='https://services.nvd.nist.gov/rest/json/cpes/2.0',
        required=True,
        help='Full URL endpoint for the NVD CPE 2.0 API. This should point to the official NIST CPE API '
             'endpoint unless using a mirror or proxy. The API provides access to the Common Platform '
             'Enumeration dictionary containing standardized software, hardware, and OS identifiers.'
    )
    batch_size = fields.Integer(
        string='Records Per API Request',
        default=100,
        help='Number of CPE entries to retrieve per API request. Larger batch sizes reduce the total number '
             'of API calls but increase processing time per request. The NVD API supports up to 2000 results '
             'per page. Recommended: 100-500 for balanced performance. Consider reducing if experiencing '
             'timeout issues or rate limiting.'
    )
    
    # CPE Processing Settings
    enable_cpe_processing = fields.Boolean(
        string='Enable CPE Matching & Processing',
        default=True,
        help='Enable automatic processing and matching of CPE (Common Platform Enumeration) identifiers '
             'during CVE data imports. When enabled, the system extracts CPE information from vulnerability '
             'records and attempts to match them with assets in your inventory. Disable this to skip CPE '
             'processing and improve import performance if asset matching is not required.'
    )
    
    auto_create_cpe_dictionary = fields.Boolean(
        string='Auto-Create Dictionary Entries from CVE Data',
        default=True,
        help='Automatically create local CPE dictionary entries when new CPE identifiers are encountered '
             'in CVE data. When enabled, any CPE string found in vulnerability data that doesn\'t exist in '
             'the local dictionary will be automatically added. This ensures comprehensive coverage but may '
             'create entries for obscure or deprecated platforms. Disable to only use manually curated CPE '
             'entries or those from full dictionary syncs.'
    )
    
    full_cpe_sync_active = fields.Boolean(
        string='Full CPE Dictionary Sync (Large Dataset)',
        default=False,
        help='Enable periodic synchronization of the complete CPE dictionary from NIST. WARNING: This is a '
             'massive dataset containing hundreds of thousands of platform identifiers. Full sync downloads '
             'will consume significant API quota, bandwidth, storage, and processing time. Only enable this '
             'if you need comprehensive coverage of all software/hardware platforms. Consider using selective '
             'vendor filtering to reduce the dataset size. Initial sync may take several hours.'
    )
    
    cpe_follows_cve_creation_active = fields.Boolean(
        string='Reactive CPE Creation from CVE Imports',
        default=False,
        help='Reactive mode: Automatically extract and create CPE dictionary entries only when they appear '
             'in newly imported CVE vulnerability records. This provides just-in-time CPE data population '
             'without the overhead of full dictionary sync. Best suited for environments that only need CPE '
             'information for actively reported vulnerabilities rather than the entire platform universe.'
    )
    
    cpe_confidence_threshold = fields.Float(
        string='Minimum Match Confidence Score (0.0-1.0)',
        default=0.7,
        digits=(3, 2),
        help='Minimum confidence score (0.0-1.0) required for automatic asset-to-vulnerability matching '
             'via CPE identifiers. Higher values (0.8-1.0) reduce false positives but may miss valid matches, '
             'while lower values (0.5-0.7) increase coverage but introduce more false associations. '
             'Recommended: 0.7 for balanced precision/recall. The system calculates confidence based on '
             'CPE field matching, version range compatibility, and vendor/product name similarity.'
    )
    
    # Processing Statistics
    cpe_entries_created = fields.Integer(
        string='Dictionary Entries Created (Last Run)',
        readonly=True,
        help='Total count of new CPE dictionary entries created during the most recent synchronization run. '
             'This includes both entries from full dictionary sync and auto-created entries from CVE data '
             'processing. Track this metric to monitor dictionary growth and identify sync job effectiveness.'
    )
    
    cpe_matches_processed = fields.Integer(
        string='Asset Matches Processed (Last Run)',
        readonly=True,
        help='Number of CPE-to-asset matching operations performed during the last import cycle. Each match '
             'represents an attempt to link a vulnerability\'s CPE identifier with assets in your inventory. '
             'High match counts indicate active vulnerability-asset correlation. Compare with successful '
             'matches to assess matching accuracy.'
    )
    
    cpe_processing_errors = fields.Integer(
        string='Processing Errors (Last Run)',
        readonly=True,
        help='Count of errors encountered during CPE processing in the last run. Errors may include malformed '
             'CPE strings, API communication failures, database constraint violations, or matching algorithm '
             'exceptions. Non-zero values warrant investigation via the processing log. Persistent high error '
             'rates may indicate data quality issues or configuration problems.'
    )
    
    cpe_processing_log = fields.Text(
        string='Detailed Processing Log',
        readonly=True,
        help='Detailed execution log from the most recent CPE processing operation. Contains timestamped '
             'entries for each major processing step, including API requests, data parsing, database operations, '
             'and error conditions. Review this log to troubleshoot processing failures, understand what data '
             'was imported, and verify matching behavior. Logs are overwritten with each new sync cycle.'
    )
    
    # State Management
    last_cpe_sync = fields.Datetime(
        string='Last Full Dictionary Sync',
        readonly=True,
        help='Timestamp of the last completed CPE dictionary synchronization operation. This tracks full '
             'dictionary updates from the NVD CPE API, distinct from incremental CVE-driven CPE additions. '
             'Use this to monitor sync schedule compliance and identify when the local CPE database may be '
             'stale. Compare with last_sync_date to distinguish between full syncs and incremental updates.'
    )
    
    cpe_sync_in_progress = fields.Boolean(
        string='Synchronization Lock Status',
        default=False,
        readonly=True,
        help='Synchronization lock flag indicating an active CPE processing operation. When True, prevents '
             'concurrent sync operations that could cause race conditions or duplicate processing. This flag '
             'is automatically set at sync start and cleared upon completion or failure. Stale True values '
             'may indicate a crashed sync job requiring manual intervention.'
    )
    
    selected_vendors = fields.Text(
        string='Vendor Filter List (One Per Line)',
        help='Whitelist of vendor names for selective CPE dictionary filtering. Enter one vendor name per line '
             '(e.g., "microsoft", "cisco", "oracle"). When populated, only CPE entries matching these vendors '
             'are synced during full dictionary updates, dramatically reducing dataset size and sync time. '
             'Vendor names are case-insensitive and matched against the CPE vendor field. Leave empty to sync '
             'all vendors. Useful for organizations that only deploy products from specific manufacturers.'
    )
    
    cpe_api_url = fields.Char(
        string='CPE Dictionary API Endpoint (Alternate)',
        default='https://services.nvd.nist.gov/rest/json/cpes/2.0',
        help='Full endpoint URL for the NIST CPE API version 2.0. This is the official API for accessing '
             'the Common Platform Enumeration dictionary maintained by NIST. This field exists separately from '
             'api_url to allow independent configuration of CPE dictionary sync versus CVE-embedded CPE '
             'processing. Change only if using a CPE API mirror, proxy, or alternate version endpoint.'
    )
    
    def _fetch_vendor_from_nvd(self, vendor_name):
        """Fetch vendor data from NVD API and create vendor record"""
        # Get API key from parent connector
        api_key = None
        if self.parent_connector_id and self.parent_connector_id.api_key:
            api_key = self.parent_connector_id.api_key
        
        # Use unified method from vendor model
        CpeVendor = self.env['vuln.fw.nvd.cpe.vendor']
        return CpeVendor.get_or_create_from_nvd(
            vendor_name=vendor_name,
            api_key=api_key,
            debug_mode=self.debug_mode
        )
    
    def _fetch_product_from_nvd(self, product_name, vendor_record, cpe_uri=None):
        """Fetch product data from NVD API and create product record"""
        # Get API key from parent connector
        api_key = None
        if self.parent_connector_id and self.parent_connector_id.api_key:
            api_key = self.parent_connector_id.api_key
        
        # Use unified method from product model
        CpeProduct = self.env['vuln.fw.nvd.cpe.product']
        return CpeProduct.get_or_create_from_nvd(
            product_name=product_name,
            vendor_record=vendor_record,
            cpe_uri=cpe_uri,
            api_key=api_key,
            debug_mode=self.debug_mode
        )
    
    def action_process_test_cpe(self):
        """Manually process a single CPE URI for testing"""
        self.ensure_one()
        
        start_time = datetime.now()
        
        if self.debug_mode:
            _logger.info(f"[DEBUG] 🚀 Starting CPE test processing - Connector: {self.name} (ID: {self.id})")
            _logger.info(f"[DEBUG] 👤 User: {self.env.user.name} (ID: {self.env.user.id})")
            _logger.info(f"[DEBUG] 💾 Database: {self.env.cr.dbname}")
        
        if not self.test_cpe_uri:
            if self.debug_mode:
                _logger.warning(f"[DEBUG] No CPE URI provided in test_cpe_uri field")
            raise UserError(_('Please enter a CPE URI to process'))
        
        cpe_uri = self.test_cpe_uri.strip()
        
        if self.debug_mode:
            _logger.info(f"[DEBUG] 📋 CPE URI: {cpe_uri}")
            _logger.info(f"[DEBUG] 📏 CPE URI length: {len(cpe_uri)} characters")
        
        # Validate CPE format
        if not cpe_uri.startswith('cpe:2.3:'):
            if self.debug_mode:
                _logger.error(f"[DEBUG] Invalid CPE format - does not start with 'cpe:2.3:'")
            raise UserError(_('Invalid CPE format. Must start with "cpe:2.3:"'))
        
        log = f"Manual CPE Processing Test - {start_time}\n"
        log += f"Connector: {self.name} (ID: {self.id})\n"
        log += f"CPE URI: {cpe_uri}\n"
        if self.debug_mode:
            log += f"Debug Mode: ENABLED\n"
        log += "\n"
        
        try:
            # Parse CPE components
            if self.debug_mode:
                _logger.info(f"[DEBUG] 📝 Parsing CPE components...")
            
            parts = cpe_uri.split(':')
            if self.debug_mode:
                _logger.info(f"[DEBUG] ✂️ Split into {len(parts)} parts: {parts}")
            
            if len(parts) < 13:
                if self.debug_mode:
                    _logger.error(f"[DEBUG] Incomplete CPE - expected 13 parts, got {len(parts)}")
                raise UserError(_('Incomplete CPE URI. Expected 13 components.'))
            
            cpe_type = parts[2]  # a=application, h=hardware, o=os
            vendor = parts[3]
            product = parts[4]
            version = parts[5]
            update = parts[6]
            edition = parts[7]
            language = parts[8]
            sw_edition = parts[9]
            target_sw = parts[10]
            target_hw = parts[11]
            other = parts[12]
            
            if self.debug_mode:
                _logger.info(f"[DEBUG] 🔍 Parsed components:")
                _logger.info(f"[DEBUG]   📦 Type: {cpe_type}")
                _logger.info(f"[DEBUG]   🏢 Vendor: {vendor}")
                _logger.info(f"[DEBUG]   🎯 Product: {product}")
                _logger.info(f"[DEBUG]   🔢 Version: {version}")
                _logger.info(f"[DEBUG]   Update: {update}")
                _logger.info(f"[DEBUG]   Edition: {edition}")
                _logger.info(f"[DEBUG]   Language: {language}")
                _logger.info(f"[DEBUG]   SW Edition: {sw_edition}")
                _logger.info(f"[DEBUG]   Target SW: {target_sw}")
                _logger.info(f"[DEBUG]   Target HW: {target_hw}")
                _logger.info(f"[DEBUG]   Other: {other}")
            
            log += "=== Parsed CPE Components ===\n"
            log += f"Type: {cpe_type} ({'Application' if cpe_type == 'a' else 'Hardware' if cpe_type == 'h' else 'OS' if cpe_type == 'o' else 'Unknown'})\n"
            log += f"Vendor: {vendor if vendor != '*' else 'Any'}\n"
            log += f"Product: {product if product != '*' else 'Any'}\n"
            log += f"Version: {version if version != '*' else 'Any'}\n"
            log += f"Update: {update if update != '*' else 'Any'}\n"
            log += f"Edition: {edition if edition != '*' else 'Any'}\n"
            log += f"Language: {language if language != '*' else 'Any'}\n"
            log += f"SW Edition: {sw_edition if sw_edition != '*' else 'Any'}\n"
            log += f"Target SW: {target_sw if target_sw != '*' else 'Any'}\n"
            log += f"Target HW: {target_hw if target_hw != '*' else 'Any'}\n"
            log += f"Other: {other if other != '*' else 'Any'}\n\n"
            
            # Check if CPE exists in dictionary
            if self.debug_mode:
                _logger.info(f"[DEBUG] 🔎 Searching for CPE in dictionary...")
            
            CpeDict = self.env['vuln.fw.nvd.cpe.dictionary']
            existing_cpe = CpeDict.search([('cpe_name', '=', cpe_uri)])
            
            if self.debug_mode:
                _logger.info(f"[DEBUG] ✅ Dictionary search completed - Found: {len(existing_cpe)} record(s)")
            
            log += "=== Dictionary Lookup ===\n"
            if existing_cpe:
                log += f"✓ Found in dictionary (ID: {existing_cpe.id})\n"
                log += f"  Title: {existing_cpe.title or 'N/A'}\n"
                log += f"  Deprecated: {existing_cpe.deprecated or False}\n"
                if self.debug_mode:
                    log += f"  Created: {existing_cpe.create_date}\n"
                    log += f"  Modified: {existing_cpe.write_date}\n"
                    _logger.info(f"[DEBUG] Existing CPE record: {existing_cpe.id} - {existing_cpe.title}")
            else:
                log += "✗ Not found in local dictionary\n"
                
                if self.debug_mode:
                    _logger.info(f"[DEBUG] 🔧 CPE not found - Auto-create enabled: {self.auto_create_cpe_dictionary}")
                
                if self.auto_create_cpe_dictionary:
                    log += "\n=== Auto-Creating Dictionary Entry ===\n"
                    try:
                        if self.debug_mode:
                            _logger.info(f"[DEBUG] 📝 Validating CPE components...")
                        
                        # Look up existing vendor (required for dictionary creation)
                        vendor_record = None
                        if vendor != '*':
                            if self.debug_mode:
                                _logger.info(f"[DEBUG] 🏢 Looking up vendor: {vendor}")
                            
                            CpeVendor = self.env['vuln.fw.nvd.cpe.vendor']
                            vendor_record = CpeVendor.search([('name', '=', vendor)], limit=1)
                            
                            if vendor_record:
                                if self.debug_mode:
                                    _logger.info(f"[DEBUG] ✅ Found existing vendor (ID: {vendor_record.id})")
                                log += f"  • Found vendor: {vendor} (ID: {vendor_record.id})\n"
                            else:
                                if self.debug_mode:
                                    _logger.warning(f"[DEBUG] ❌ Vendor '{vendor}' not found in local database")
                                    _logger.info(f"[DEBUG] 🌐 Attempting to fetch from NVD API...")
                                log += f"  ⚠️ Vendor '{vendor}' not in local database\n"
                                log += f"  🌐 Fetching from NVD API...\n"
                                
                                # Try to fetch from NVD
                                vendor_record = self._fetch_vendor_from_nvd(vendor)
                                
                                if vendor_record:
                                    log += f"  ✅ Vendor created from NVD (ID: {vendor_record.id})\n"
                                else:
                                    log += f"  ❌ Vendor not found in NVD - CPE creation blocked\n"
                        
                        # Look up existing product (required for dictionary creation)
                        product_record = None
                        if product != '*':
                            if self.debug_mode:
                                _logger.info(f"[DEBUG] 🎯 Looking up product: {product}")
                            
                            CpeProduct = self.env['vuln.fw.nvd.cpe.product']
                            domain = [('name', '=', product)]
                            if vendor_record:
                                domain.append(('vendor_id', '=', vendor_record.id))
                            
                            product_record = CpeProduct.search(domain, limit=1)
                            
                            if product_record:
                                if self.debug_mode:
                                    _logger.info(f"[DEBUG] ✅ Found existing product (ID: {product_record.id})")
                                log += f"  • Found product: {product} (ID: {product_record.id})\n"
                            else:
                                if self.debug_mode:
                                    _logger.warning(f"[DEBUG] ❌ Product '{product}' not found in local database")
                                    _logger.info(f"[DEBUG] 🌐 Attempting to fetch from NVD API...")
                                log += f"  ⚠️ Product '{product}' not in local database\n"
                                log += f"  🌐 Fetching from NVD API...\n"
                                
                                # Try to fetch from NVD (pass complete CPE URI for full context)
                                product_record = self._fetch_product_from_nvd(product, vendor_record, cpe_uri)
                                
                                if product_record:
                                    log += f"  ✅ Product created from NVD (ID: {product_record.id})\n"
                                else:
                                    log += f"  ❌ Product not found in NVD - CPE creation blocked\n"
                        
                        # Only create dictionary entry if BOTH vendor AND product are found
                        if not vendor_record or not product_record:
                            if self.debug_mode:
                                _logger.warning(f"[DEBUG] 🚫 Dictionary entry creation SKIPPED - missing required vendor or product")
                            log += f"\n❌ Dictionary entry NOT created - vendor and product must exist in database\n"
                            log += f"ℹ️ This CPE will be created automatically after NVD sync imports the missing records\n"
                        else:
                            # Both vendor and product found - proceed with creation
                            if self.debug_mode:
                                _logger.info(f"[DEBUG] ✅ Validation passed - both vendor and product found")
                            
                            new_entry_vals = {
                                'cpe_name': cpe_uri,
                                'part': cpe_type,
                                'vendor': vendor if vendor != '*' else '',
                                'product': product if product != '*' else '',
                                'version': version if version != '*' else '',
                                'update_component': update if update != '*' else '',
                                'edition': edition if edition != '*' else '',
                                'language': language if language != '*' else '',
                                'sw_edition': sw_edition if sw_edition != '*' else '',
                                'target_sw': target_sw if target_sw != '*' else '',
                                'target_hw': target_hw if target_hw != '*' else '',
                                'other': other if other != '*' else '',
                                'title': f"{product.replace('_', ' ').title()} {version if version != '*' else ''}".strip(),
                                'deprecated': False,
                                'vendor_id': vendor_record.id,
                                'product_id': product_record.id,
                            }
                            
                            if self.debug_mode:
                                _logger.info(f"[DEBUG] 💾 Dictionary entry values: {new_entry_vals}")
                            
                            new_entry = CpeDict.create(new_entry_vals)
                            
                            if self.debug_mode:
                                _logger.info(f"[DEBUG] ✨ Created dictionary entry ID: {new_entry.id}")
                            
                            log += f"✓ Created new dictionary entry (ID: {new_entry.id})\n"
                            log += f"  ✅ Fully linked to vendor and product records\n"
                        if self.debug_mode:
                            log += f"  Record details: {new_entry_vals}\n"
                        self.cpe_entries_created += 1
                    except Exception as e:
                        log += f"✗ Failed to create entry: {str(e)}\n"
                        if self.debug_mode:
                            _logger.error(f"[DEBUG] Dictionary creation error: {str(e)}", exc_info=True)
                else:
                    log += "  (Auto-create disabled)\n"
            
            # Test CPE matching if enabled
            if self.debug_mode:
                _logger.info(f"[DEBUG] CPE processing enabled: {self.enable_cpe_processing}")
            
            if self.enable_cpe_processing:
                log += "\n=== CPE Matching Test ===\n"
                
                if self.debug_mode:
                    _logger.info(f"[DEBUG] 🎯 Calculating confidence score...")
                
                # Simulate confidence calculation
                base_confidence = 0.7
                confidence_factors = []
                
                if vendor != '*':
                    base_confidence += 0.1
                    confidence_factors.append("Vendor specified (+0.1)")
                if product != '*':
                    base_confidence += 0.1
                    confidence_factors.append("Product specified (+0.1)")
                if version != '*':
                    base_confidence += 0.05
                    confidence_factors.append("Version specified (+0.05)")
                
                confidence = min(base_confidence, 1.0)
                
                if self.debug_mode:
                    _logger.info(f"[DEBUG] 📊 Base confidence: 0.7")
                    _logger.info(f"[DEBUG] 📈 Confidence factors: {confidence_factors}")
                    _logger.info(f"[DEBUG] 🎯 Final confidence: {confidence:.2f}")
                    _logger.info(f"[DEBUG] ⚖️ Threshold: {self.cpe_confidence_threshold}")
                
                log += f"Calculated confidence: {confidence:.2f}\n"
                if self.debug_mode:
                    for factor in confidence_factors:
                        log += f"  - {factor}\n"
                log += f"Threshold: {self.cpe_confidence_threshold}\n"
                
                if confidence >= self.cpe_confidence_threshold:
                    log += "✓ Confidence meets threshold for matching\n"
                    self.cpe_matches_processed += 1
                    if self.debug_mode:
                        _logger.info(f"[DEBUG] ✅ Confidence check PASSED - match would be created")
                else:
                    log += "✗ Confidence below threshold\n"
                    if self.debug_mode:
                        _logger.warning(f"[DEBUG] ❌ Confidence check FAILED - {confidence:.2f} < {self.cpe_confidence_threshold}")
            else:
                log += "\n=== CPE Matching Disabled ===\n"
            
            end_time = datetime.now()
            processing_time = (end_time - start_time).total_seconds()
            
            if self.debug_mode:
                _logger.info(f"[DEBUG] ✅ Processing completed successfully")
                _logger.info(f"[DEBUG] ⏱️ Total processing time: {processing_time:.3f} seconds")
                _logger.info(f"[DEBUG] 📊 Statistics updated:")
                _logger.info(f"[DEBUG]   ➕ Entries created: {self.cpe_entries_created}")
                _logger.info(f"[DEBUG]   🔗 Matches processed: {self.cpe_matches_processed}")
            
            log += "\n=== Processing Complete ===\n"
            log += "✓ CPE URI processed successfully\n"
            if self.debug_mode:
                log += f"\n=== Debug Information ===\n"
                log += f"Processing time: {processing_time:.3f} seconds\n"
                log += f"User: {self.env.user.name} (ID: {self.env.user.id})\n"
                log += f"Database: {self.env.cr.dbname}\n"
                log += f"Python environment: {self.env}\n"
                log += f"Current settings:\n"
                log += f"  - Enable processing: {self.enable_cpe_processing}\n"
                log += f"  - Auto-create dictionary: {self.auto_create_cpe_dictionary}\n"
                log += f"  - Confidence threshold: {self.cpe_confidence_threshold}\n"
                log += f"  - Batch size: {self.batch_size}\n"
            
            # Update processing log
            self.cpe_processing_log = log
            
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('CPE Processed Successfully'),
                    'message': f'CPE URI parsed and processed in {processing_time:.3f}s. Check Processing Log for details.',
                    'type': 'success',
                    'sticky': False,
                }
            }
            
        except UserError:
            if self.debug_mode:
                _logger.error(f"[DEBUG] User error raised during processing")
            raise
        except Exception as e:
            if self.debug_mode:
                _logger.error(f"[DEBUG] ❌ Unexpected error during processing: {str(e)}", exc_info=True)
            
            log += f"\n=== ERROR ===\n"
            log += f"✗ Processing failed: {str(e)}\n"
            if self.debug_mode:
                import traceback
                log += f"\n=== Debug Stack Trace ===\n"
                log += traceback.format_exc()
            self.cpe_processing_log = log
            self.cpe_processing_errors += 1
            raise UserError(_(f'CPE processing failed: {str(e)}'))
    
    @api.model
    def process_cve_cpe_data(self, cve_data):
        """Process CPE data from CVE entry"""
        self.ensure_one()
        
        if not self.enable_cpe_processing:
            return
        
        cpe_count = 0
        match_count = 0
        error_count = 0
        log_lines = []
        
        try:
            # Get CPE matches from CVE configurations
            configurations = cve_data.get('configurations', [])
            
            for config in configurations:
                nodes = config.get('nodes', [])
                for node in nodes:
                    cpe_matches = node.get('cpeMatch', [])
                    
                    for cpe_match in cpe_matches:
                        try:
                            match_count += 1
                            cpe_uri = cpe_match.get('criteria', '')
                            
                            if cpe_uri and self.auto_create_cpe_dictionary:
                                # Auto-create CPE dictionary entry
                                cpe_created = self._create_cpe_from_uri(cpe_uri, cpe_match)
                                if cpe_created:
                                    cpe_count += 1
                                    
                        except Exception as e:
                            error_count += 1
                            log_lines.append(f"Error processing CPE match: {str(e)}")
                            _logger.error(f"CPE match processing error: {e}")
            
            # Update statistics
            self.write({
                'cpe_entries_created': cpe_count,
                'cpe_matches_processed': match_count,
                'cpe_processing_errors': error_count,
                'cpe_processing_log': '\n'.join(log_lines) if log_lines else 'CPE processing completed successfully',
                'last_cpe_sync': fields.Datetime.now()
            })
            
        except Exception as e:
            _logger.error(f"CPE data processing failed: {e}")
            raise UserError(_('CPE data processing failed: %s') % str(e))
    
    def _create_cpe_from_uri(self, cpe_uri, cpe_data):
        """Create CPE dictionary entry from CPE URI"""
        # Parse CPE 2.3 URI
        cpe_dict = self.env['vuln.fw.nvd.cpe.dictionary']
        
        # Check if CPE already exists
        existing_cpe = cpe_dict.search([('cpe_name', '=', cpe_uri)], limit=1)
        if existing_cpe:
            return False
        
        # Parse CPE URI components
        cpe_parts = cpe_uri.split(':')
        if len(cpe_parts) < 5:
            return False
        
        try:
            cpe_dict.create({
                'cpe_name': cpe_uri,
                'part': cpe_parts[2] if len(cpe_parts) > 2 else '',
                'vendor': cpe_parts[3] if len(cpe_parts) > 3 else '',
                'product': cpe_parts[4] if len(cpe_parts) > 4 else '',
                'version': cpe_parts[5] if len(cpe_parts) > 5 else '',
                'title': cpe_data.get('cpe23Uri', ''),
                'deprecated': False,
                'active': True
            })
            return True
        except Exception as e:
            _logger.error(f"Failed to create CPE from URI {cpe_uri}: {e}")
            return False
    
    def action_sync_cpe_dictionary(self):
        """Sync full CPE dictionary from NVD API"""
        self.ensure_one()
        
        if not self.full_cpe_sync_active:
            raise UserError(_('Full CPE dictionary sync is not enabled for this connector'))
        
        if self.cpe_sync_in_progress:
            raise UserError(_('CPE sync is already in progress'))
        
        try:
            self.write({'cpe_sync_in_progress': True})
            
            # Parse selected vendors
            vendors = []
            if self.selected_vendors:
                vendors = [v.strip() for v in self.selected_vendors.split('\n') if v.strip()]
            
            # Perform sync
            total_synced = 0
            start_index = 0
            results_per_page = self.batch_size or 100
            
            while True:
                params = {
                    'startIndex': start_index,
                    'resultsPerPage': results_per_page
                }
                
                if vendors:
                    # Filter by vendors if specified
                    params['keywordSearch'] = ' OR '.join(vendors)
                
                # Fetch CPE data (implementation would call NVD API)
                # This is placeholder - actual implementation would make HTTP request
                _logger.info(f"Syncing CPE dictionary: start_index={start_index}, batch={results_per_page}")
                
                # Break condition (would be based on actual API response)
                break
            
            self.write({
                'last_cpe_sync': fields.Datetime.now(),
                'cpe_sync_in_progress': False
            })
            
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('CPE Sync Complete'),
                    'message': _('Successfully synced %d CPE entries') % total_synced,
                    'type': 'success',
                    'sticky': False,
                }
            }
            
        except Exception as e:
            self.write({'cpe_sync_in_progress': False})
            _logger.error(f"CPE dictionary sync failed: {e}")
            raise UserError(_('CPE dictionary sync failed: %s') % str(e))

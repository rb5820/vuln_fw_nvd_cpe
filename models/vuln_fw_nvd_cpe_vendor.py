# -*- coding: utf-8 -*-

from odoo import api, fields, models, _
import logging

_logger = logging.getLogger(__name__)


class VulnFwNvdCpeVendor(models.Model):
    """
    CPE Vendor model for managing software/hardware vendors in CPE entries.
    Normalizes vendor information across CPE entries from NVD.
    """
    _name = 'vuln.fw.nvd.cpe.vendor'
    _description = 'NVD CPE Vendor'
    _order = 'name'
    _rec_name = 'name'
    
    # === CORE FIELDS ===
    name = fields.Char(
        string='Vendor Name',
        required=True,
        index=True,
        help='Normalized vendor name from CPE (e.g., microsoft, adobe, google)'
    )
    
    custom_name = fields.Char(
        string='Custom Name',
        help='Your custom vendor name (e.g., Microsoft Corporation, Adobe Inc.)'
    )
    
    display_name = fields.Char(
        string='Display Name',
        compute='_compute_display_name',
        store=True,
        help='Human-readable vendor name. Uses custom_name if available, otherwise name'
    )
    
    description = fields.Text(
        string='Description',
        help='Vendor description or additional information'
    )
    
    website = fields.Char(
        string='Website',
        help='Vendor official website'
    )
    
    # === STATISTICS ===
    cpe_count = fields.Integer(
        string='CPE Entries',
        compute='_compute_cpe_count',
        store=True,
        help='Number of CPE dictionary entries for this vendor'
    )
    
    product_count = fields.Integer(
        string='Product Count',
        compute='_compute_product_count',
        store=True,
        help='Number of unique products from this vendor'
    )
    
    vulnerability_count = fields.Integer(
        string='Total Vulnerabilities',
        compute='_compute_vulnerability_count',
        store=True,
        help='Total vulnerabilities across all vendor products'
    )
    
    # === NVD SYNC METADATA ===
    nvd_last_sync = fields.Datetime(
        string='Last NVD Sync',
        readonly=True,
        help='Last time products were synced from NVD API'
    )
    
    nvd_product_count = fields.Integer(
        string='NVD Product Count',
        readonly=True,
        help='Total number of products found in NVD for this vendor'
    )
    
    # === METADATA ===
    active = fields.Boolean(
        string='Active',
        default=True,
        help='Whether this vendor is active'
    )
    
    debug_mode = fields.Boolean(
        string='Debug Mode',
        default=False,
        store=True,
        copy=False,
        help='Enable detailed emoji logging for API operations'
    )
    
    company_id = fields.Many2one(
        'res.company',
        string='Company',
        default=lambda self: self.env.company
    )
    
    # === RELATIONSHIPS ===
    cpe_dictionary_ids = fields.One2many(
        'vuln.fw.nvd.cpe.dictionary',
        'vendor_id',
        string='CPE Dictionary Entries'
    )
    
    product_ids = fields.One2many(
        'vuln.fw.nvd.cpe.product',
        'vendor_id',
        string='Products'
    )
    
    reference_ids = fields.Many2many(
        comodel_name='vuln.fw.nvd.reference',
        relation='vuln_fw_nvd_ref_cpe_vendor_rel',
        column1='vendor_id',
        column2='reference_id',
        string='References',
        help='Reference URLs for this vendor'
    )
    
    # === COMPUTED FIELDS ===
    @api.depends('custom_name', 'name')
    def _compute_display_name(self):
        """Compute display name: use custom_name if available, otherwise name."""
        for vendor in self:
            vendor.display_name = vendor.custom_name or vendor.name or ''
    
    @api.depends('cpe_dictionary_ids')
    def _compute_cpe_count(self):
        """Compute CPE count for this vendor."""
        for record in self:
            record.cpe_count = len(record.cpe_dictionary_ids)
    
    @api.depends('product_ids')
    def _compute_product_count(self):
        """Compute product count for this vendor."""
        for record in self:
            record.product_count = len(record.product_ids)
    
    def _compute_vulnerability_count(self):
        """Compute total vulnerability count for this vendor."""
        for record in self:
            # This would be computed from vulnerability data if available
            # For now, we can leave it at 0 or compute from CPE matches
            record.vulnerability_count = 0
    
    # === CONSTRAINTS ===
    _sql_constraints = [
        ('name_company_unique', 'unique(name, company_id)', 
         'Vendor name must be unique per company!')
    ]
    
    # === API METHODS ===
    @api.model
    def get_or_create_from_nvd(self, vendor_name, api_key=None, debug_mode=False):
        """
        Get existing vendor or create from NVD API if exists there.
        
        Args:
            vendor_name (str): Vendor name to search for
            api_key (str, optional): NVD API key for authenticated requests
            debug_mode (bool): Enable detailed logging
            
        Returns:
            recordset: vendor record if found/created, empty recordset if not found in NVD
        """
        import requests
        
        if debug_mode:
            _logger.info(f"[VENDOR] 🔍 Looking up vendor: {vendor_name}")
        
        # First check if vendor exists locally
        vendor = self.search([('name', '=', vendor_name)], limit=1)
        if vendor:
            if debug_mode:
                _logger.info(f"[VENDOR] ✅ Found existing vendor (ID: {vendor.id})")
            return vendor
        
        if debug_mode:
            _logger.info(f"[VENDOR] ❌ Vendor not in local database")
            _logger.info(f"[VENDOR] 🌐 Making NVD API call to verify vendor...")
        
        try:
            # Query NVD API
            base_url = 'https://services.nvd.nist.gov/rest/json/cpes/2.0'
            params = {
                'cpeMatchString': f'cpe:2.3:*:{vendor_name}:*',
                'resultsPerPage': 1
            }
            
            headers = {}
            if api_key:
                headers['apiKey'] = api_key
                if debug_mode:
                    _logger.info(f"[VENDOR] 🔑 Using authenticated API")
            else:
                if debug_mode:
                    _logger.info(f"[VENDOR] 🆓 Using free API")
            
            if debug_mode:
                _logger.info(f"[VENDOR] 📤 Request: {base_url} with params {params}")
            
            response = requests.get(base_url, params=params, headers=headers, timeout=30)
            
            if debug_mode:
                _logger.info(f"[VENDOR] 📥 Response status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                products = data.get('products', [])
                
                if debug_mode:
                    _logger.info(f"[VENDOR] 📊 Found {len(products)} product(s) for vendor")
                
                if products:
                    # Vendor verified in NVD, create local record
                    vendor = self.create({
                        'name': vendor_name,
                        'description': f'Auto-created from NVD API on {fields.Datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
                    })
                    
                    if debug_mode:
                        _logger.info(f"[VENDOR] ✅ Created vendor from NVD (ID: {vendor.id})")
                    
                    return vendor
                else:
                    if debug_mode:
                        _logger.warning(f"[VENDOR] ⚠️ Vendor '{vendor_name}' not found in NVD")
                    return self.env['vuln.fw.nvd.cpe.vendor']
            else:
                if debug_mode:
                    _logger.error(f"[VENDOR] ❌ NVD API error: {response.status_code}")
                return self.env['vuln.fw.nvd.cpe.vendor']
                
        except Exception as e:
            _logger.error(f"[VENDOR] ❌ Error fetching vendor from NVD: {str(e)}")
            return self.env['vuln.fw.nvd.cpe.vendor']
    
    # === ACTIONS ===
    def action_sync_from_nvd(self):
        """Sync vendor data and products from NVD API."""
        self.ensure_one()
        import requests
        from datetime import datetime
        
        # Get API key from parent connector if available
        connector = self.env['vuln.fw.nvd.connector'].search([('active', '=', True)], limit=1)
        api_key = connector.api_key if connector else None
        
        if self.debug_mode:
            _logger.info(f"🚀 [VENDOR] Starting NVD sync for vendor: {self.name}")
            _logger.info(f"👤 [VENDOR] User: {self.env.user.name} (ID: {self.env.user.id})")
            _logger.info(f"💾 [VENDOR] Database: {self.env.cr.dbname}")
        
        try:
            # Query NVD API for all products from this vendor
            base_url = 'https://services.nvd.nist.gov/rest/json/cpes/2.0'
            params = {
                'cpeMatchString': f'cpe:2.3:*:{self.name}:*',
                'resultsPerPage': 100  # Get more results
            }
            
            headers = {}
            if api_key:
                headers['apiKey'] = api_key
                if self.debug_mode:
                    _logger.info(f"🔑 [VENDOR] Using authenticated API")
            else:
                if self.debug_mode:
                    _logger.info(f"🆓 [VENDOR] Using free API (rate limited)")
            
            if self.debug_mode:
                _logger.info(f"📤 [VENDOR] Request: {base_url}")
                _logger.info(f"📋 [VENDOR] Params: {params}")
            
            response = requests.get(base_url, params=params, headers=headers, timeout=30)
            
            if self.debug_mode:
                _logger.info(f"📥 [VENDOR] Response status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                products = data.get('products', [])
                total_results = data.get('totalResults', 0)
                
                if self.debug_mode:
                    _logger.info(f"📊 [VENDOR] Found {len(products)} products in this page")
                    _logger.info(f"📈 [VENDOR] Total results available: {total_results}")
                    
                    # Debug: Show top-level response structure
                    _logger.info(f"🔍 [VENDOR] Response top-level keys: {list(data.keys())}")
                    
                    # Debug: Show detailed structure of first product
                    if products:
                        first_product = products[0]
                        _logger.info(f"🎯 [VENDOR] First product structure:")
                        _logger.info(f"   📋 Top-level keys: {list(first_product.keys())}")
                        
                        # Show CPE details
                        cpe = first_product.get('cpe', {})
                        _logger.info(f"   📦 CPE object keys: {list(cpe.keys())}")
                        _logger.info(f"   🆔 cpeNameId: {cpe.get('cpeNameId', 'N/A')}")
                        _logger.info(f"   📛 cpeName: {cpe.get('cpeName', 'N/A')}")
                        _logger.info(f"   📅 created: {cpe.get('created', 'N/A')}")
                        _logger.info(f"   🔄 lastModified: {cpe.get('lastModified', 'N/A')}")
                        _logger.info(f"   ⚠️ deprecated: {cpe.get('deprecated', 'N/A')}")
                        _logger.info(f"   🔖 deprecatedBy: {cpe.get('deprecatedBy', 'N/A')}")
                        
                        # Show titles
                        titles = cpe.get('titles', [])
                        if titles:
                            _logger.info(f"   📝 titles: {titles}")
                        
                        # Show refs
                        refs = cpe.get('refs', [])
                        if refs:
                            _logger.info(f"   🔗 refs count: {len(refs)}")
                            _logger.info(f"   🔗 refs sample: {refs[:2] if len(refs) > 2 else refs}")
                            
                            # Create or link vendor reference records
                            reference_ids = []
                            for ref in refs:
                                ref_url = ref.get('ref', '')
                                ref_type = ref.get('type', '').lower()
                                if ref_url:
                                    # Map NVD ref types to our selection values
                                    type_mapping = {
                                        'version': 'version',
                                        'vendor': 'vendor',
                                        'product': 'product',
                                        'advisory': 'advisory',
                                        'change log': 'version',
                                        'release notes': 'version',
                                    }
                                    mapped_type = type_mapping.get(ref_type, 'other')
                                    
                                    # Get or create reference
                                    reference = self.env['vuln.fw.nvd.reference'].get_or_create_reference(
                                        url=ref_url,
                                        ref_type=mapped_type,
                                        entity_name=self.name,
                                        entity_type='vendor'
                                    )
                                    if reference:
                                        reference_ids.append(reference.id)
                            
                            # Link references to vendor
                            if reference_ids:
                                self.write({'reference_ids': [(6, 0, reference_ids)]})
                                _logger.info(f"✅ [VENDOR] Linked {len(reference_ids)} references to vendor")
                        
                        # Show complete first product for reference
                        import json
                        _logger.info(f"   📄 Complete first product JSON:")
                        _logger.info(json.dumps(first_product, indent=2))
                
                # Update vendor with sync data
                sync_timestamp = datetime.now()
                sync_msg = f"Last NVD sync: {sync_timestamp.strftime('%Y-%m-%d %H:%M:%S')} - Found {total_results} products"
                self.write({
                    'description': f"{self.description or ''}\n\n{sync_msg}".strip(),
                    'nvd_last_sync': sync_timestamp,
                    'nvd_product_count': total_results,
                })
                
                if self.debug_mode:
                    _logger.info(f"✅ [VENDOR] Sync completed - {total_results} products found in NVD")
                
                return {
                    'type': 'ir.actions.client',
                    'tag': 'display_notification',
                    'params': {
                        'title': _('NVD Sync Completed'),
                        'message': _(f'Found {total_results} products for vendor "{self.name}" in NVD database.'),
                        'type': 'success',
                        'sticky': False,
                    }
                }
            else:
                error_msg = f"NVD API returned status {response.status_code}"
                if self.debug_mode:
                    _logger.error(f"❌ [VENDOR] {error_msg}")
                
                return {
                    'type': 'ir.actions.client',
                    'tag': 'display_notification',
                    'params': {
                        'title': _('Sync Failed'),
                        'message': error_msg,
                        'type': 'danger',
                        'sticky': True,
                    }
                }
        
        except Exception as e:
            error_msg = f"Error syncing from NVD: {str(e)}"
            _logger.error(f"❌ [VENDOR] {error_msg}")
            
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Sync Error'),
                    'message': error_msg,
                    'type': 'danger',
                    'sticky': True,
                }
            }
    
    def action_view_cpe_entries(self):
        """View CPE dictionary entries for this vendor."""
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': _(('CPE Entries for %s', self.name)),
            'res_model': 'vuln.fw.nvd.cpe.dictionary',
            'view_mode': 'list,form',
            'domain': [('vendor_id', '=', self.id)],
            'context': {'default_vendor_id': self.id}
        }
    
    def action_view_products(self):
        """View products for this vendor."""
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': _('Products from %s', self.name),
            'res_model': 'vuln.fw.nvd.cpe.product',
            'view_mode': 'list,form',
            'domain': [('vendor_id', '=', self.id)],
            'context': {'default_vendor_id': self.id}
        }

# -*- coding: utf-8 -*-

from odoo import api, fields, models, _
import logging
import json

_logger = logging.getLogger(__name__)


class VulnFwNvdCpeProduct(models.Model):
    """
    CPE Product model for managing software/hardware products in CPE entries.
    Normalizes product information across CPE entries from NVD.
    """
    _name = 'vuln.fw.nvd.cpe.product'
    _description = 'NVD CPE Product'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'name'
    _rec_name = 'display_name'
    
    # === CORE FIELDS ===
    name = fields.Char(
        string='Product Name',
        required=True,
        index=True,
        tracking=True,
        help='Product name from CPE (e.g., windows, chrome, acrobat_reader)'
    )
    
    display_name = fields.Char(
        string='Display Name',
        compute='_compute_display_name',
        store=True,
        help='Human-readable product name with version'
    )
    
    title = fields.Char(
        string='Product Title',
        help='Full product title from NVD metadata'
    )
    
    description = fields.Text(
        string='Description',
        help='Product description or additional information'
    )
    
    category = fields.Selection([
        ('application', 'Application'),
        ('operating_system', 'Operating System'),
        ('hardware', 'Hardware'),
        ('firmware', 'Firmware'),
        ('library', 'Library/Runtime'),
        ('service', 'Service'),
        ('other', 'Other')
    ], string='Category', tracking=True, help='Product category')
    
    cpe_part = fields.Selection([
        ('a', 'Application'),
        ('h', 'Hardware'), 
        ('o', 'Operating System')
    ], string='CPE Part', required=True, default='a', tracking=True,
        help='CPE 2.3 part identifier')
    
    # === VERSION INFO ===
    version = fields.Char(
        string='Version',
        help='Product version (e.g., 1.0.0, 2023, *)'
    )
    
    version_pattern = fields.Char(
        string='Version Pattern',
        help='Version pattern for matching (e.g., 10.*, 2023.*)'
    )
    
    # === CPE 2.3 FIELDS ===
    cpe_uri = fields.Char(
        string='CPE 2.3 URI',
        index=True,
        help='Complete CPE 2.3 URI'
    )
    
    cpe_update = fields.Char(
        string='Update',
        default='*',
        help='CPE update field'
    )
    
    cpe_edition = fields.Char(
        string='Edition',
        default='*',
        help='CPE edition field'
    )
    
    cpe_language = fields.Char(
        string='Language',
        default='*',
        help='CPE language field'
    )
    
    cpe_sw_edition = fields.Char(
        string='SW Edition',
        default='*',
        help='CPE software edition field'
    )
    
    cpe_target_sw = fields.Char(
        string='Target SW',
        default='*',
        help='CPE target software field'
    )
    
    cpe_target_hw = fields.Char(
        string='Target HW',
        default='*',
        help='CPE target hardware field'
    )
    
    cpe_other = fields.Char(
        string='Other',
        default='*',
        help='CPE other information field'
    )
    
    # === NVD STATUS ===
    deprecated = fields.Boolean(
        string='Deprecated',
        default=False,
        tracking=True,
        help='Whether this CPE product is deprecated in NVD'
    )
    
    deprecated_by = fields.Text(
        string='Deprecated By',
        help='JSON array of CPE URIs that replace this deprecated CPE'
    )
    
    not_registered_in_nvd = fields.Boolean(
        string='Not Registered in NVD',
        default=False,
        tracking=True,
        help='Indicates this product is not registered in NVD'
    )
    
    nvd_cpe_id = fields.Char(
        string='NVD CPE ID',
        index=True,
        help='UUID identifier for this CPE entry from NVD (cpeNameId)'
    )
    
    nvd_created = fields.Datetime(
        string='NVD Created Date',
        help='Date when this CPE was created in NVD'
    )
    
    nvd_last_modified = fields.Datetime(
        string='NVD Last Modified',
        help='Date when this CPE was last modified in NVD'
    )
    
    nvd_references = fields.Text(
        string='NVD References',
        help='JSON-stored references/links from NVD (URLs and types)'
    )
    
    nvd_titles = fields.Text(
        string='NVD Titles (All Languages)',
        help='JSON-stored titles from NVD in all available languages (title and lang)'
    )
    
    # === STATISTICS ===
    cpe_count = fields.Integer(
        string='CPE Entries',
        compute='_compute_cpe_count',
        store=True,
        help='Number of CPE dictionary entries for this product'
    )
    
    vulnerability_count = fields.Integer(
        string='Vulnerabilities',
        compute='_compute_vulnerability_count',
        store=True,
        help='Number of vulnerabilities affecting this product'
    )
    
    # match_count field removed - match model doesn't link to products yet
    
    # === METADATA ===
    active = fields.Boolean(
        string='Active',
        default=True,
        help='Whether this product is active'
    )
    
    debug_mode = fields.Boolean(
        string='Debug Mode',
        default=False,
        store=True,
        copy=False,
        help='Enable detailed debug logging for this product'
    )
    
    test_cpe_uri = fields.Char(
        string='Test CPE URI',
        help='Enter a CPE 2.3 URI for manual testing and validation. '
             'Example: cpe:2.3:a:microsoft:edge_chromium:143.0.3650.66:*:*:*:-:windows:*:*'
    )
    
    company_id = fields.Many2one(
        'res.company',
        string='Company',
        default=lambda self: self.env.company
    )
    
    # === RELATIONSHIPS ===
    vendor_id = fields.Many2one(
        'vuln.fw.nvd.cpe.vendor',
        string='Vendor',
        required=True,
        ondelete='cascade',
        index=True,
        help='Product vendor'
    )
    
    reference_ids = fields.Many2many(
        comodel_name='vuln.fw.nvd.reference',
        relation='vuln_fw_nvd_ref_cpe_product_rel',
        column1='product_id',
        column2='reference_id',
        string='References',
        help='Reference URLs for this product'
    )
    
    # === HARDWARE-FIRMWARE RELATIONSHIPS ===
    runs_on_hardware_ids = fields.Many2many(
        comodel_name='vuln.fw.nvd.cpe.product',
        relation='vuln_fw_nvd_cpe_firmware_hardware_rel',
        column1='firmware_id',
        column2='hardware_id',
        string='Runs On Hardware',
        domain="[('cpe_part', '=', 'h')]",
        help='Hardware products this firmware/OS runs on (for cpe_part=o)'
    )
    
    firmware_ids = fields.Many2many(
        comodel_name='vuln.fw.nvd.cpe.product',
        relation='vuln_fw_nvd_cpe_firmware_hardware_rel',
        column1='hardware_id',
        column2='firmware_id',
        string='Compatible Firmware',
        domain="[('cpe_part', '=', 'o')]",
        help='Firmware/OS that runs on this hardware (for cpe_part=h)'
    )
    
    runs_on_count = fields.Integer(
        string='Runs On Count',
        compute='_compute_runs_on_count',
        help='Number of hardware products this firmware runs on'
    )
    
    firmware_count = fields.Integer(
        string='Firmware Count',
        compute='_compute_firmware_count',
        help='Number of firmware/OS compatible with this hardware'
    )
    
    # === VERSION HIERARCHY ===
    parent_id = fields.Many2one(
        'vuln.fw.nvd.cpe.product',
        string='Parent Product',
        index=True,
        ondelete='cascade',
        help='Parent product in version hierarchy (e.g., 1.0 is parent of 1.0.1)'
    )
    
    child_ids = fields.One2many(
        'vuln.fw.nvd.cpe.product',
        'parent_id',
        string='Child Versions',
        help='Child product versions in hierarchy'
    )
    
    version_level = fields.Integer(
        string='Version Level',
        help='Depth level in version hierarchy (0=root, 1=minor, 2=patch, etc.)',
        default=0,
        compute='_compute_version_level',
        store=True
    )
    
    cpe_dictionary_ids = fields.One2many(
        'vuln.fw.nvd.cpe.dictionary',
        'product_id',
        string='CPE Dictionary Entries'
    )
    
    # === COMPUTED FIELDS ===
    @api.depends('name', 'version', 'vendor_id.name')
    def _compute_display_name(self):
        """Compute display name with vendor and version."""
        for record in self:
            parts = []
            if record.vendor_id:
                parts.append(record.vendor_id.name.capitalize())
            if record.name:
                parts.append(record.name.replace('_', ' ').title())
            if record.version and record.version not in ('*', '-'):
                parts.append(f"v{record.version}")
            record.display_name = ' '.join(parts) if parts else 'Unnamed Product'
    
    @api.depends('cpe_dictionary_ids')
    def _compute_cpe_count(self):
        """Compute CPE count for this product."""
        for record in self:
            record.cpe_count = len(record.cpe_dictionary_ids)
    
    @api.depends('parent_id')
    def _compute_version_level(self):
        """Compute version level in hierarchy."""
        for record in self:
            if not record.parent_id:
                record.version_level = 0
            else:
                parent = record.parent_id
                level = 1
                while parent.parent_id:
                    parent = parent.parent_id
                    level += 1
                record.version_level = level
    
    def _compute_vulnerability_count(self):
        """Compute vulnerability count for this product."""
        for record in self:
            # This would be computed from vulnerability data if available
            record.vulnerability_count = 0
    
    @api.depends('runs_on_hardware_ids')
    def _compute_runs_on_count(self):
        """Compute count of hardware products this firmware runs on."""
        for record in self:
            record.runs_on_count = len(record.runs_on_hardware_ids)
    
    @api.depends('firmware_ids')
    def _compute_firmware_count(self):
        """Compute count of firmware/OS compatible with this hardware."""
        for record in self:
            record.firmware_count = len(record.firmware_ids)
    
    # _compute_match_count removed - match model doesn't link to products yet
    
    # === CVE MODULE INTEGRATION (OPTIONAL) ===
    @api.model
    def _cve_module_available(self):
        """
        Check if CVE module is installed and available.
        Returns True if vuln_fw_nvd_cve module is installed.
        """
        try:
            module = self.env['ir.module.module'].search([
                ('name', '=', 'vuln_fw_nvd_cve'),
                ('state', '=', 'installed')
            ], limit=1)
            return bool(module)
        except Exception as e:
            _logger.debug("Error checking CVE module availability: %s", str(e))
            return False
    
    def _get_cve_enhancement_model(self):
        """
        Get CVE enhancement model if available.
        Returns the model recordset or False if not available.
        """
        if self._cve_module_available():
            try:
                return self.env['vuln.fw.nvd.cve.enhancement']
            except KeyError:
                _logger.warning("CVE module installed but enhancement model not found")
                return False
        return False
    
    # === CONSTRAINTS ===
    _sql_constraints = [
        ('name_vendor_version_unique', 'unique(name, vendor_id, version, company_id)', 
         'Product name, vendor and version combination must be unique per company!')
    ]
    
    # === API METHODS ===
    @api.model
    def get_or_create_from_nvd(self, product_name, vendor_record=None, cpe_uri=None, api_key=None, debug_mode=False):
        """
        Get existing product or create from NVD API if exists there.
        
        Args:
            product_name (str): Product name to search for
            vendor_record (recordset, optional): Vendor record to link product to
            cpe_uri (str, optional): Complete CPE 2.3 URI for extracting version and other fields
            api_key (str, optional): NVD API key for authenticated requests
            debug_mode (bool): Enable detailed logging
            
        Returns:
            recordset: product record if found/created, empty recordset if not found in NVD
        """
        import requests
        
        # Parse version from CPE URI if provided
        version = None
        cpe_part = 'a'
        if cpe_uri and cpe_uri.startswith('cpe:2.3:'):
            parts = cpe_uri.split(':')
            if len(parts) >= 6:
                cpe_part = parts[2] if parts[2] in ['a', 'h', 'o'] else 'a'
                version = parts[5] if parts[5] != '*' else None
        
        if debug_mode:
            version_info = f" (version: {version})" if version else ""
            _logger.info(f"[PRODUCT] 🔍 Looking up product: {product_name}{version_info}")
        
        # First check if product exists locally
        domain = [('name', '=', product_name)]
        if vendor_record:
            domain.append(('vendor_id', '=', vendor_record.id))
        if version:
            domain.append(('version', '=', version))
        
        product = self.search(domain, limit=1)
        if product:
            if debug_mode:
                _logger.info(f"[PRODUCT] ✅ Found existing product (ID: {product.id})")
            return product
        
        if debug_mode:
            _logger.info(f"[PRODUCT] ❌ Product not in local database")
            _logger.info(f"[PRODUCT] 🌐 Making NVD API call to verify product...")
        
        try:
            # Query NVD API
            base_url = 'https://services.nvd.nist.gov/rest/json/cpes/2.0'
            vendor_part = vendor_record.name if vendor_record else '*'
            params = {
                'cpeMatchString': f'cpe:2.3:*:{vendor_part}:{product_name}:*',
                'resultsPerPage': 1
            }
            
            headers = {}
            if api_key:
                headers['apiKey'] = api_key
                if debug_mode:
                    _logger.info(f"[PRODUCT] 🔑 Using authenticated API")
            else:
                if debug_mode:
                    _logger.info(f"[PRODUCT] 🆓 Using free API")
            
            if debug_mode:
                _logger.info(f"[PRODUCT] 📤 Request: {base_url} with params {params}")
            
            response = requests.get(base_url, params=params, headers=headers, timeout=30)
            
            if debug_mode:
                _logger.info(f"[PRODUCT] 📥 Response status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                products = data.get('products', [])
                
                if debug_mode:
                    _logger.info(f"[PRODUCT] 📊 Found {len(products)} matching product(s)")
                
                if products:
                    # Product verified in NVD, create local record
                    # Extract NVD metadata from first matching product
                    first_cpe = products[0].get('cpe', {})
                    
                    product_vals = {
                        'name': product_name,
                        'cpe_part': cpe_part,
                        'description': f'Auto-created from NVD API on {fields.Datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
                        'deprecated': first_cpe.get('deprecated', False),
                        'nvd_cpe_id': first_cpe.get('cpeNameId', ''),
                    }
                    
                    # Extract and store title
                    titles = first_cpe.get('titles', [])
                    if titles:
                        product_vals['title'] = titles[0].get('title', '')
                        # Store all titles with languages as JSON
                        product_vals['nvd_titles'] = json.dumps(titles)
                    
                    # Store references as JSON
                    refs = first_cpe.get('refs', [])
                    if refs:
                        product_vals['nvd_references'] = json.dumps(refs)
                        
                        # Create or link reference records
                        reference_ids = []
                        if self.debug_mode:
                            _logger.info("🔗 [PRODUCT DEBUG] Processing %d references from NVD...", len(refs))
                        
                        try:
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
                                    
                                    if self.debug_mode:
                                        _logger.info("🔗 [PRODUCT DEBUG]   Processing: %s (NVD Type: %s -> Mapped: %s)", 
                                                   ref_url[:80], ref_type, mapped_type)
                                    
                                    # Get or create reference
                                    reference = self.env['vuln.fw.nvd.reference'].get_or_create_reference(
                                        url=ref_url,
                                        ref_type=mapped_type,
                                        entity_name=product_name,
                                        entity_type='product'
                                    )
                                    if reference:
                                        reference_ids.append(reference.id)
                                        if self.debug_mode:
                                            _logger.info("🔗 [PRODUCT DEBUG]   ✅ Reference %d: ID=%s, URL=%s", 
                                                       len(reference_ids), reference.id, ref_url[:80])
                                    else:
                                        if self.debug_mode:
                                            _logger.warning("🔗 [PRODUCT DEBUG]   ⚠️ No reference returned for: %s", ref_url[:80])
                            
                            if reference_ids:
                                product_vals['reference_ids'] = [(6, 0, reference_ids)]
                                if self.debug_mode:
                                    _logger.info("🔗 [PRODUCT DEBUG] ✅ Prepared %d reference IDs for linking: %s", 
                                               len(reference_ids), reference_ids)
                            else:
                                if self.debug_mode:
                                    _logger.warning("🔗 [PRODUCT DEBUG] ⚠️ No reference IDs collected")
                                    
                        except Exception as e:
                            _logger.error("❌ [PRODUCT DEBUG] Error processing references: %s", str(e))
                            import traceback
                            _logger.error("❌ [PRODUCT DEBUG] Traceback: %s", traceback.format_exc())
                    
                    # Store deprecated_by as JSON
                    deprecated_by = first_cpe.get('deprecatedBy', [])
                    if deprecated_by:
                        product_vals['deprecated_by'] = json.dumps(deprecated_by)
                    
                    # Parse timestamps
                    nvd_created_str = first_cpe.get('created', '')
                    nvd_last_modified_str = first_cpe.get('lastModified', '')
                    
                    if nvd_created_str:
                        try:
                            from datetime import datetime
                            product_vals['nvd_created'] = datetime.fromisoformat(nvd_created_str.replace('Z', '+00:00'))
                        except:
                            pass
                    
                    if nvd_last_modified_str:
                        try:
                            from datetime import datetime
                            product_vals['nvd_last_modified'] = datetime.fromisoformat(nvd_last_modified_str.replace('Z', '+00:00'))
                        except:
                            pass
                    
                    if vendor_record:
                        product_vals['vendor_id'] = vendor_record.id
                    if version:
                        product_vals['version'] = version
                    if cpe_uri:
                        product_vals['cpe_uri'] = cpe_uri
                    
                    product = self.create(product_vals)
                    
                    if debug_mode:
                        version_msg = f" with version {version}" if version else ""
                        _logger.info(f"[PRODUCT] ✅ Created product from NVD (ID: {product.id}){version_msg}")
                    
                    return product
                else:
                    if debug_mode:
                        _logger.warning(f"[PRODUCT] ⚠️ Product '{product_name}' not found in NVD")
                    return self.env['vuln.fw.nvd.cpe.product']
            else:
                if debug_mode:
                    _logger.error(f"[PRODUCT] ❌ NVD API error: {response.status_code}")
                return self.env['vuln.fw.nvd.cpe.product']
                
        except Exception as e:
            _logger.error(f"[PRODUCT] ❌ Error fetching product from NVD: {str(e)}")
            return self.env['vuln.fw.nvd.cpe.product']
    
    # === ACTIONS ===
    def action_view_cpe_entries(self):
        """View CPE dictionary entries for this product."""
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': _('CPE Entries for %s', self.display_name),
            'res_model': 'vuln.fw.nvd.cpe.dictionary',
            'view_mode': 'list,form',
            'domain': [('product_id', '=', self.id)],
            'context': {'default_product_id': self.id}
        }
    
    def action_view_cves(self):
        """View all CVEs related to this product's CPE entries."""
        self.ensure_one()
        
        # Collect all unique CVE IDs from CPE Dictionary entries
        all_cves = self.env['vuln.fw.nvd.cve.enhancement']
        for cpe_entry in self.cpe_dictionary_ids:
            if hasattr(cpe_entry, 'cve_ids'):
                all_cves |= cpe_entry.cve_ids
        
        return {
            'type': 'ir.actions.act_window',
            'name': _('CVEs for %s', self.display_name),
            'res_model': 'vuln.fw.nvd.cve.enhancement',
            'view_mode': 'list,form',
            'domain': [('id', 'in', all_cves.ids)],
            'context': {
                'search_default_group_by_severity': 1,
            }
        }
    
    def action_add_to_dictionary(self):
        """Create a CPE Dictionary entry from this product."""
        self.ensure_one()
        
        # Build CPE URI if not already built
        if not self.cpe_uri:
            self.cpe_uri = self._build_cpe_uri()
        
        # Check if dictionary entry already exists
        existing = self.env['vuln.fw.nvd.cpe.dictionary'].search([
            ('cpe_name', '=', self.cpe_uri),
            ('product_id', '=', self.id)
        ], limit=1)
        
        if existing:
            return {
                'type': 'ir.actions.act_window',
                'name': _('Existing CPE Dictionary Entry'),
                'res_model': 'vuln.fw.nvd.cpe.dictionary',
                'res_id': existing.id,
                'view_mode': 'form',
                'target': 'current',
            }
        
        # Create new dictionary entry
        vals = {
            'cpe_name': self.cpe_uri,
            'title': self.title or f"{self.vendor_id.name} {self.name} {self.version or ''}".strip(),
            'product_id': self.id,
            'part': self.cpe_part,
            'vendor': self.vendor_id.name,
            'product': self.name,
            'version': self.version or '*',
            'update_component': self.cpe_update or '*',
            'edition': self.cpe_edition or '*',
            'language': self.cpe_language or '*',
            'sw_edition': self.cpe_sw_edition or '*',
            'target_sw': self.cpe_target_sw or '*',
            'target_hw': self.cpe_target_hw or '*',
            'other': self.cpe_other or '*',
            'deprecated': self.deprecated,
        }
        
        cpe_entry = self.env['vuln.fw.nvd.cpe.dictionary'].create(vals)
        
        return {
            'type': 'ir.actions.act_window',
            'name': _('New CPE Dictionary Entry'),
            'res_model': 'vuln.fw.nvd.cpe.dictionary',
            'res_id': cpe_entry.id,
            'view_mode': 'form',
            'target': 'current',
        }
    
    # action_view_matches removed - match model doesn't link to products yet
    
    # === CPE URI BUILDING METHODS ===
    def _encode_cpe_component(self, component, is_version=False):
        r"""Encode CPE component according to CPE 2.3 specification (RFC 5849).
        
        CPE 2.3 escape sequences:
        - & → \&
        - ! → \!
        - " → \"
        - * → \*
        - + → \+
        - , → \,
        - : → \:
        - ; → \;
        - < → \<
        - = → \=
        - > → \>
        - @ → \@
        - [ → \[
        - \ → \\
        - ] → \]
        - ^ → \^
        - ` → \`
        - { → \{
        - | → \|
        - } → \}
        - ~ → \~
        """
        if not component:
            return '*'
        
        component_str = str(component).strip()
        if not component_str:
            return '*'
            
        # Special CPE values
        if component_str in ['*', '-']:
            return component_str
            
        # Special handling for version field
        if is_version and component_str == '*':
            return '-'
        
        # Lowercase and normalize spaces
        encoded = component_str.lower()
        encoded = encoded.replace(' ', '_')
        
        # Escape CPE 2.3 special characters (RFC 5849)
        # Must handle backslash first to avoid double-escaping
        encoded = encoded.replace('\\', '\\\\')
        encoded = encoded.replace('&', '\\&')
        encoded = encoded.replace('!', '\\!')
        encoded = encoded.replace('"', '\\"')
        encoded = encoded.replace('*', '\\*')
        encoded = encoded.replace('+', '\\+')
        encoded = encoded.replace(',', '\\,')
        encoded = encoded.replace(':', '\\:')
        encoded = encoded.replace(';', '\\;')
        encoded = encoded.replace('<', '\\<')
        encoded = encoded.replace('=', '\\=')
        encoded = encoded.replace('>', '\\>')
        encoded = encoded.replace('@', '\\@')
        encoded = encoded.replace('[', '\\[')
        encoded = encoded.replace(']', '\\]')
        encoded = encoded.replace('^', '\\^')
        encoded = encoded.replace('`', '\\`')
        encoded = encoded.replace('{', '\\{')
        encoded = encoded.replace('|', '\\|')
        encoded = encoded.replace('}', '\\}')
        encoded = encoded.replace('~', '\\~')
        
        return encoded or '*'
    
    def _determine_cpe_part_from_category(self):
        """
        Map product category to CPE part (a/h/o).
        Returns: 'a' for Application, 'h' for Hardware, 'o' for Operating System
        """
        # Special handling for firmware products
        if self.name and self.name.lower().endswith('_firmware'):
            return 'o'
            
        if not self.category:
            return self._detect_cpe_part_from_name()
        
        category_mapping = {
            'operating_system': 'o',
            'hardware': 'h', 
            'firmware': 'o',
            'application': 'a',
            'library': 'a',
            'service': 'a',
            'other': 'a'
        }
        
        return category_mapping.get(self.category, 'a')
    
    def _detect_cpe_part_from_name(self):
        """Detect CPE part from product name when category is not set."""
        product_name = (self.name or '').lower()
        
        # Operating Systems
        os_keywords = [
            'windows', 'linux', 'ubuntu', 'centos', 'redhat', 'debian', 'suse',
            'macos', 'ios', 'android', 'unix', 'aix', 'solaris', 'freebsd'
        ]
        
        if any(keyword in product_name for keyword in os_keywords):
            return 'o'
        
        # Hardware
        hardware_keywords = [
            'server', 'switch', 'router', 'firewall', 'appliance', 'storage',
            'printer', 'scanner', 'laptop', 'desktop', 'tablet', 'phone'
        ]
        
        if any(keyword in product_name for keyword in hardware_keywords):
            return 'h'
        
        return 'a'
    
    def _build_cpe_uri(self):
        """
        Build CPE 2.3 URI for this product.
        Format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
        """
        if not self.vendor_id or not self.name:
            _logger.debug("Cannot build CPE URI: vendor_id=%s, name=%s", self.vendor_id, self.name)
            return ''
        
        cpe_part = self.cpe_part or 'a'
        
        # Handle version component
        if not self.version or self.version.strip() == '' or self.version.lower() == 'no version':
            version_component = '*'
        else:
            version_component = self._encode_cpe_component(self.version, is_version=True)
        
        if self.debug_mode:
            _logger.info("🔧 [DEBUG] Building CPE URI: vendor=%s, product=%s, version=%s, part=%s", 
                         self.vendor_id.name, self.name, self.version, cpe_part)
        
        # Build the 13 components of CPE 2.3 URI
        components = [
            'cpe',
            '2.3',
            cpe_part,
            self._encode_cpe_component(self.vendor_id.name),
            self._encode_cpe_component(self.name),
            version_component,
            self._encode_cpe_component(self.cpe_update or '*'),
            self._encode_cpe_component(self.cpe_edition or '*'),
            self._encode_cpe_component(self.cpe_language or '*'),
            self._encode_cpe_component(self.cpe_sw_edition or '*'),
            self._encode_cpe_component(self.cpe_target_sw or '*'),
            self._encode_cpe_component(self.cpe_target_hw or '*'),
            self._encode_cpe_component(self.cpe_other or '*')
        ]
        
        uri = ':'.join(components)
        
        if self.debug_mode:
            _logger.info("🔧 [DEBUG] CPE URI components: part=%s, vendor=%s, product=%s, version=%s, update=%s, edition=%s, language=%s, sw_edition=%s, target_sw=%s, target_hw=%s, other=%s",
                         cpe_part,
                         components[3],
                         components[4],
                         components[5],
                         components[6],
                         components[7],
                         components[8],
                         components[9],
                         components[10],
                         components[11],
                         components[12])
        
        _logger.info("Built CPE URI: %s for product '%s' version='%s' (version_component='%s')", 
                    uri, self.name, self.version or 'None', version_component)
        return uri
    
    def action_build_cpe_uri(self):
        """Manually build/rebuild CPE URI for this product."""
        for record in self:
            if record.vendor_id and record.name:
                record.cpe_uri = record._build_cpe_uri()
                return {
                    'type': 'ir.actions.client',
                    'tag': 'display_notification',
                    'params': {
                        'title': _('CPE URI Built Successfully'),
                        'message': _('CPE URI has been generated: %s') % record.cpe_uri,
                        'type': 'success',
                        'sticky': False,
                    }
                }
            else:
                return {
                    'type': 'ir.actions.client',
                    'tag': 'display_notification',
                    'params': {
                        'title': _('Missing Required Fields'),
                        'message': _('Please ensure Vendor and Product Name are filled.'),
                        'type': 'warning',
                        'sticky': False,
                    }
                }
    
    @api.model
    def action_build_all_cpe_uris(self):
        """Batch build CPE URIs for all products that don't have them."""
        products_without_uri = self.search([
            ('cpe_uri', 'in', [False, '']),
            ('vendor_id', '!=', False),
            ('name', '!=', False)
        ])
        
        built_count = 0
        for product in products_without_uri:
            product.cpe_uri = product._build_cpe_uri()
            built_count += 1
            _logger.info("Built CPE URI for product %s: %s", product.id, product.cpe_uri)
        
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Batch CPE URI Build Complete'),
                'message': _('Built CPE URIs for %d products') % built_count,
                'type': 'success',
                'sticky': True,
            }
        }
    
    def action_find_related_cpes(self):
        """Search NVD CPE dictionary for related products and link them."""
        self.ensure_one()
        
        if not self.vendor_id or not self.name:
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Missing Information'),
                    'message': _('Product must have both vendor and name to find related CPEs.'),
                    'type': 'warning'
                }
            }
        
        # Search for related CPE dictionary entries
        vendor_name = self.vendor_id.name.lower()
        product_name = self.name.lower()
        
        # Log CPE URI and search details
        cpe_uri = self._build_cpe_uri()
        _logger.info("🔍 Searching for related CPEs")
        _logger.info("   CPE URI: %s", cpe_uri)
        _logger.info("   Vendor: %s, Product: %s", vendor_name, product_name)
        
        # Build search domain for CPE dictionary - case-insensitive partial match
        # Search for CPEs with matching vendor and product (linked or unlinked)
        domain = [
            ('vendor', '=ilike', f'%{vendor_name}%'),
            ('product', '=ilike', f'%{product_name}%'),
        ]
        
        _logger.debug("Search domain: %s", domain)
        
        related_cpes = self.env['vuln.fw.nvd.cpe.dictionary'].search(domain)
        
        _logger.info("Found %d related CPE entries", len(related_cpes))
        
        if related_cpes:
            # Separate unlinked and already-linked CPEs
            unlinked_cpes = related_cpes.filtered(lambda cpe: not cpe.product_id)
            linked_cpes = related_cpes.filtered(lambda cpe: cpe.product_id)
            
            if unlinked_cpes:
                unlinked_cpes.write({'product_id': self.id})
                _logger.info("✅ Linked %d unlinked CPE entries to product %s", len(unlinked_cpes), self.id)
            
            if linked_cpes:
                _logger.info("ℹ️  %d CPE entries already linked to other products", len(linked_cpes))
            
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Related CPEs Found'),
                    'message': _('Found and linked %d CPE entries to this product') % len(related_cpes),
                    'type': 'success',
                    'sticky': True,
                }
            }
        else:
            _logger.warning("No related CPE entries found for vendor=%s, product=%s", vendor_name, product_name)
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('No Related CPEs'),
                    'message': _('No unlinked CPE entries found for this product in the dictionary.'),
                    'type': 'info'
                }
            }
    
    def _get_or_create_version_parent(self, version_str):
        """
        Recursively get or create parent version hierarchy.
        
        For version "1.2.3.4", creates:
        - "1" with parent = self
        - "1.2" with parent = "1"
        - "1.2.3" with parent = "1.2"
        - "1.2.3.4" with parent = "1.2.3"
        """
        self.ensure_one()
        
        version_parts = version_str.split('.')
        if len(version_parts) <= 1:
            # Single component or empty - parent is the main product
            return self.id
        
        # Remove last component to get parent version
        parent_version_str = '.'.join(version_parts[:-1])
        
        # Check if parent version product exists
        parent_product = self.env['vuln.fw.nvd.cpe.product'].search([
            ('vendor_id', '=', self.vendor_id.id),
            ('name', '=', self.name),
            ('version', '=', parent_version_str)
        ], limit=1)
        
        if parent_product:
            if self.debug_mode:
                _logger.info("🔍 [DEBUG] Found existing parent version: v%s (ID: %s)", 
                           parent_version_str, parent_product.id)
            return parent_product.id
        
        # Recursively get/create grandparent
        grandparent_id = self._get_or_create_version_parent(parent_version_str)
        
        # Create the parent version product
        parent_product = self.env['vuln.fw.nvd.cpe.product'].create({
            'vendor_id': self.vendor_id.id,
            'name': self.name,
            'version': parent_version_str,
            'cpe_part': self.cpe_part or 'a',
            'category': self.category,
            'parent_id': grandparent_id,
            'description': _('Auto-created version hierarchy from NVD API'),
        })
        
        _logger.info("🌳 Created intermediate version: %s v%s (ID: %s, parent_id: %s)", 
                   self.name, parent_version_str, parent_product.id, grandparent_id)
        
        if self.debug_mode:
            _logger.info("🔍 [DEBUG] Created version hierarchy node: v%s with parent ID: %s", 
                       parent_version_str, grandparent_id)
        
        return parent_product.id
    
    def action_query_nvd_cpe_api(self):
        """Query NVD CPE API using the built CPE URI (matchString parameter)."""
        self.ensure_one()
        
        if self.debug_mode:
            _logger.info("🚀 [PRODUCT DEBUG] Starting NVD CPE API query for product: %s (ID: %s)", self.name, self.id)
            _logger.info("🔍 [PRODUCT DEBUG] Product details - Vendor: %s, Version: %s, CPE Part: %s", 
                        self.vendor_id.name if self.vendor_id else 'N/A', self.version, self.cpe_part)
        
        if not self.cpe_uri:
            if self.debug_mode:
                _logger.warning("❌ [PRODUCT DEBUG] No CPE URI found - cannot query NVD API")
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Missing CPE URI'),
                    'message': _('Please build the CPE URI first before querying the NVD API.'),
                    'type': 'warning'
                }
            }
        
        if self.debug_mode:
            _logger.info("🔑 [PRODUCT DEBUG] Using CPE URI: %s", self.cpe_uri)
        
        try:
            import requests
            from urllib.parse import urlencode
            
            base_url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
            params = {
                'cpeMatchString': self.cpe_uri,
                'resultsPerPage': 100
            }
            
            headers = {
                'User-Agent': 'Odoo-NVD-Connector/1.0',
                'Accept': 'application/json'
            }
            
            # Add API key if available
            connector = self.env['vuln.fw.nvd.connector'].search([], limit=1)
            if connector and connector.api_key:
                headers['apiKey'] = connector.api_key
                if self.debug_mode:
                    _logger.info("🔐 [PRODUCT DEBUG] Using authenticated API (API key configured)")
            else:
                if self.debug_mode:
                    _logger.info("🆓 [PRODUCT DEBUG] Using free API (no API key)")
            
            # Build full URL for logging
            full_url = f"{base_url}?{urlencode(params)}"
            
            if self.debug_mode:
                _logger.info("🌐 [PRODUCT DEBUG] API Endpoint: %s", base_url)
                _logger.info("📤 [PRODUCT DEBUG] Request Parameters: %s", params)
                _logger.info("📤 [PRODUCT DEBUG] Request Headers: %s", {k: '***' if k == 'apiKey' else v for k, v in headers.items()})
                _logger.info("🔗 [PRODUCT DEBUG] Full URL: %s", full_url)
            
            _logger.info("Querying NVD CPE API with cpeMatchString: %s", self.cpe_uri)
            
            response = requests.get(base_url, params=params, headers=headers, timeout=30)
            
            if self.debug_mode:
                _logger.info("📥 [PRODUCT DEBUG] Response Status Code: %s", response.status_code)
                _logger.info("📥 [PRODUCT DEBUG] Response Size: %s bytes", len(response.content))
                _logger.info("📥 [PRODUCT DEBUG] Response Headers: %s", dict(response.headers))
            
            _logger.info("NVD CPE API response status: %s", response.status_code)
            
            # Log response body for debugging
            try:
                response_json = response.json()
                if self.debug_mode:
                    _logger.info("📊 [PRODUCT DEBUG] Full Response JSON structure:")
                    _logger.info("📊 [PRODUCT DEBUG] Response keys: %s", list(response_json.keys()))
                    _logger.info("📊 [PRODUCT DEBUG] Response JSON (single line): %s", json.dumps(response_json))
            except Exception as json_err:
                if self.debug_mode:
                    _logger.error("❌ [PRODUCT DEBUG] Failed to parse JSON response: %s", str(json_err))
                    _logger.debug("📄 [PRODUCT DEBUG] Raw response text (first 1000 chars): %s", response.text[:1000])
            
            if response.status_code == 404:
                _logger.warning("NVD CPE API endpoint not found (404)")
                if self.debug_mode:
                    _logger.error("❌ [PRODUCT DEBUG] 404 Error - API endpoint not found")
                    _logger.error("❌ [PRODUCT DEBUG] Request URL was: %s", full_url)
                return {
                    'type': 'ir.actions.client',
                    'tag': 'display_notification',
                    'params': {
                        'title': _('API Error'),
                        'message': _('NVD CPE API returned 404. The endpoint may be unavailable.'),
                        'type': 'error'
                    }
                }
            
            response.raise_for_status()
            
            data = response.json()
            
            cpe_items = data.get('products', [])
            total_results = data.get('totalResults', 0)
            results_per_page = data.get('resultsPerPage', 0)
            start_index = data.get('startIndex', 0)
            
            _logger.info("Found %d matching CPE entries from NVD API (total available: %d)", 
                        len(cpe_items), total_results)
            
            if self.debug_mode:
                _logger.info("🎯 [PRODUCT DEBUG] ===== NVD API RESPONSE DETAILS =====")
                _logger.info("🎯 [PRODUCT DEBUG] Total Results Available: %d", total_results)
                _logger.info("🎯 [PRODUCT DEBUG] Results Per Page: %d", results_per_page)
                _logger.info("🎯 [PRODUCT DEBUG] Start Index: %d", start_index)
                _logger.info("🎯 [PRODUCT DEBUG] Items in Response: %d", len(cpe_items))
                _logger.info("🎯 [PRODUCT DEBUG] Response Format: %s", data.get('format', 'N/A'))
                _logger.info("🎯 [PRODUCT DEBUG] Response Version: %s", data.get('version', 'N/A'))
                _logger.info("🎯 [PRODUCT DEBUG] Response Timestamp: %s", data.get('timestamp', 'N/A'))
                
                if cpe_items:
                    _logger.info("🎯 [PRODUCT DEBUG] ===== FIRST CPE ITEM STRUCTURE =====")
                    first_item = cpe_items[0]
                    _logger.info("🎯 [PRODUCT DEBUG] CPE Item Keys: %s", list(first_item.keys()))
                    
                    cpe_obj = first_item.get('cpe', {})
                    _logger.info("🎯 [PRODUCT DEBUG] CPE Object Keys: %s", list(cpe_obj.keys()))
                    _logger.info("🎯 [PRODUCT DEBUG] CPE Name: %s", cpe_obj.get('cpeName', 'N/A'))
                    _logger.info("🎯 [PRODUCT DEBUG] CPE Name ID: %s", cpe_obj.get('cpeNameId', 'N/A'))
                    _logger.info("🎯 [PRODUCT DEBUG] Deprecated: %s", cpe_obj.get('deprecated', False))
                    _logger.info("🎯 [PRODUCT DEBUG] Last Modified: %s", cpe_obj.get('lastModified', 'N/A'))
                    _logger.info("🎯 [PRODUCT DEBUG] Created: %s", cpe_obj.get('created', 'N/A'))
                    
                    titles = cpe_obj.get('titles', [])
                    if titles:
                        _logger.info("🎯 [PRODUCT DEBUG] Titles (%d):", len(titles))
                        for idx, title in enumerate(titles[:3]):  # First 3 titles
                            _logger.info("🎯 [PRODUCT DEBUG]   Title %d - Lang: %s, Value: %s", 
                                       idx + 1, title.get('lang', 'N/A'), title.get('title', 'N/A'))
                    
                    refs = cpe_obj.get('refs', [])
                    if refs:
                        _logger.info("🎯 [PRODUCT DEBUG] References (%d):", len(refs))
                        for idx, ref in enumerate(refs[:3]):  # First 3 refs
                            _logger.info("🎯 [PRODUCT DEBUG]   Ref %d - Type: %s, URL: %s", 
                                       idx + 1, ref.get('type', 'N/A'), ref.get('ref', 'N/A'))
                    
                    deprecated_by = cpe_obj.get('deprecatedBy', [])
                    if deprecated_by:
                        _logger.info("🎯 [PRODUCT DEBUG] Deprecated By (%d):", len(deprecated_by))
                        for idx, dep_cpe in enumerate(deprecated_by[:3]):
                            _logger.info("🎯 [PRODUCT DEBUG]   Replacement %d: %s - %s", 
                                       idx + 1, dep_cpe.get('cpeName', 'N/A'), dep_cpe.get('cpeNameId', 'N/A'))
                    
                    _logger.info("🎯 [PRODUCT DEBUG] ===== ADDITIONAL CPE ITEMS =====")
                    for idx, item in enumerate(cpe_items[1:6], start=2):  # Items 2-6
                        cpe = item.get('cpe', {})
                        _logger.info("🎯 [PRODUCT DEBUG] CPE Item %d: %s (ID: %s, Deprecated: %s)", 
                                   idx, cpe.get('cpeName', 'N/A'), cpe.get('cpeNameId', 'N/A'), 
                                   cpe.get('deprecated', False))
                    
                    if len(cpe_items) > 6:
                        _logger.info("🎯 [PRODUCT DEBUG] ... and %d more items", len(cpe_items) - 6)
            
            if not cpe_items:
                _logger.warning("No CPE entries found matching: %s", self.cpe_uri)
                if self.debug_mode:
                    _logger.warning("⚠️ [PRODUCT DEBUG] No CPE entries found in NVD")
                    _logger.info("⚠️ [PRODUCT DEBUG] Full response data: %s", data)
                return {
                    'type': 'ir.actions.client',
                    'tag': 'display_notification',
                    'params': {
                        'title': _('No Matches Found'),
                        'message': _('No CPE entries found in NVD API matching this URI.'),
                        'type': 'info'
                    }
                }
            
            if self.debug_mode:
                _logger.info("✅ [PRODUCT DEBUG] Successfully retrieved %d CPE results from NVD API", len(cpe_items))
            
            # Process and update product with NVD data
            if cpe_items:
                first_item = cpe_items[0]
                cpe_obj = first_item.get('cpe', {})
                
                # Update product with latest NVD data
                update_vals = {}
                
                # Collect all references from ALL CPE items (not just first)
                all_refs = []
                for item in cpe_items:
                    item_cpe = item.get('cpe', {})
                    item_refs = item_cpe.get('refs', [])
                    if item_refs:
                        all_refs.extend(item_refs)
                
                # Remove duplicate URLs
                unique_refs = {}
                for ref in all_refs:
                    url = ref.get('ref', '')
                    if url and url not in unique_refs:
                        unique_refs[url] = ref
                
                refs = list(unique_refs.values())
                
                if refs:
                    if self.debug_mode:
                        _logger.info("🔗 [PRODUCT DEBUG] Processing %d unique references from %d CPE items...", 
                                   len(refs), len(cpe_items))
                    
                    reference_ids = []
                    try:
                        for ref in refs:
                            ref_url = ref.get('ref', '')
                            ref_type = ref.get('type', '').lower().strip()
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
                                # Default to 'other' if type is missing or not recognized
                                mapped_type = type_mapping.get(ref_type, 'other') if ref_type else 'other'
                                
                                if self.debug_mode:
                                    type_display = f"'{ref_type}'" if ref_type else 'None'
                                    _logger.info("🔗 [PRODUCT DEBUG]   Processing: %s (NVD Type: %s -> Mapped: %s)", 
                                               ref_url[:80], type_display, mapped_type)
                                
                                # Get or create reference
                                reference = self.env['vuln.fw.nvd.reference'].get_or_create_reference(
                                    url=ref_url,
                                    ref_type=mapped_type,
                                    entity_name=self.name,
                                    entity_type='product'
                                )
                                if reference:
                                    reference_ids.append(reference.id)
                                    
                                    # If this is a vendor reference, also link it to the vendor
                                    if mapped_type == 'vendor' and self.vendor_id:
                                        if self.vendor_id.id not in reference.cpe_vendor_ids.ids:
                                            reference.write({'cpe_vendor_ids': [(4, self.vendor_id.id)]})
                                            if self.debug_mode:
                                                _logger.info("🔗 [PRODUCT DEBUG]   🏢 Linked vendor reference to: %s", 
                                                           self.vendor_id.display_name)
                                    
                                    if self.debug_mode:
                                        _logger.info("🔗 [PRODUCT DEBUG]   ✅ Reference %d: ID=%s, URL=%s", 
                                                   len(reference_ids), reference.id, ref_url[:80])
                                else:
                                    if self.debug_mode:
                                        _logger.warning("🔗 [PRODUCT DEBUG]   ⚠️ No reference returned for: %s", ref_url[:80])
                        
                        if reference_ids:
                            update_vals['reference_ids'] = [(6, 0, reference_ids)]
                            if self.debug_mode:
                                _logger.info("🔗 [PRODUCT DEBUG] ✅ Will link %d reference IDs: %s", 
                                           len(reference_ids), reference_ids)
                        else:
                            if self.debug_mode:
                                _logger.warning("🔗 [PRODUCT DEBUG] ⚠️ No reference IDs collected")
                                
                    except Exception as e:
                        _logger.error("❌ [PRODUCT DEBUG] Error processing references: %s", str(e))
                        import traceback
                        _logger.error("❌ [PRODUCT DEBUG] Traceback: %s", traceback.format_exc())
                elif self.debug_mode:
                    _logger.info("🔗 [PRODUCT DEBUG] No references found in any of the %d CPE items", len(cpe_items))
                
                # Update NVD metadata
                if refs:
                    update_vals['nvd_references'] = json.dumps(refs)
                
                titles = cpe_obj.get('titles', [])
                if titles:
                    update_vals['nvd_titles'] = json.dumps(titles)
                    if titles and not self.title:
                        update_vals['title'] = titles[0].get('title', '')
                
                nvd_cpe_id = cpe_obj.get('cpeNameId', '')
                if nvd_cpe_id:
                    update_vals['nvd_cpe_id'] = nvd_cpe_id
                
                # Update timestamps
                from datetime import datetime
                nvd_created_str = cpe_obj.get('created', '')
                nvd_last_modified_str = cpe_obj.get('lastModified', '')
                
                if nvd_created_str:
                    try:
                        update_vals['nvd_created'] = datetime.fromisoformat(nvd_created_str.replace('Z', '+00:00'))
                    except:
                        pass
                
                if nvd_last_modified_str:
                    try:
                        update_vals['nvd_last_modified'] = datetime.fromisoformat(nvd_last_modified_str.replace('Z', '+00:00'))
                    except:
                        pass
                
                # Write updates
                if update_vals:
                    self.write(update_vals)
                    if self.debug_mode:
                        _logger.info("✅ [PRODUCT DEBUG] Updated product with NVD data: %s", list(update_vals.keys()))
            
            message = _('Found %d matching CPE entries from NVD API. Total available: %d') % (len(cpe_items), total_results)
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('NVD CPE Query Results'),
                    'message': message,
                    'type': 'success',
                    'sticky': True,
                }
            }
            
        except Exception as e:
            _logger.error("Error querying NVD CPE API: %s", str(e), exc_info=True)
            if self.debug_mode:
                _logger.error("❌ [PRODUCT DEBUG] Exception occurred during API query")
                _logger.error("❌ [PRODUCT DEBUG] Exception type: %s", type(e).__name__)
                _logger.error("❌ [PRODUCT DEBUG] Exception message: %s", str(e))
                _logger.error("❌ [PRODUCT DEBUG] Full traceback:", exc_info=True)
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('API Query Error'),
                    'message': _('Failed to query NVD CPE API: %s') % str(e),
                    'type': 'error'
                }
            }
    
    def action_create_version_products(self):
        """Create child products from NVD API results (one per returned version)."""
        self.ensure_one()
        
        if not self.cpe_uri:
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Missing CPE URI'),
                    'message': _('Please build the CPE URI first.'),
                    'type': 'warning'
                }
            }
        
        if not self.vendor_id:
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Missing Vendor'),
                    'message': _('Please set a vendor first.'),
                    'type': 'warning'
                }
            }
        
        try:
            import requests
            from urllib.parse import urlencode
            
            base_url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
            params = {
                'cpeMatchString': self.cpe_uri,
                'resultsPerPage': 100
            }
            
            headers = {
                'User-Agent': 'Odoo-NVD-Connector/1.0',
                'Accept': 'application/json'
            }
            
            connector = self.env['vuln.fw.nvd.connector'].search([], limit=1)
            if connector and connector.api_key:
                headers['apiKey'] = connector.api_key
                if self.debug_mode:
                    _logger.info("🔍 [DEBUG] Using API key from connector")
            
            _logger.info("Querying NVD CPE API to create version products for: %s", self.cpe_uri)
            
            response = requests.get(base_url, params=params, headers=headers, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            cpe_items = data.get('products', [])
            
            _logger.info("📦 Found %d CPE items to process", len(cpe_items))
            
            if self.debug_mode:
                _logger.info("🔍 [DEBUG] Creating version products from %d CPE items", len(cpe_items))
                _logger.info("🔍 [DEBUG] Parent product: %s (vendor: %s, cpe_part: %s)", 
                            self.display_name, self.vendor_id.display_name, self.cpe_part)
            
            created_products = []
            skipped_versions = []
            
            
            for idx, cpe_item in enumerate(cpe_items, 1):
                cpe = cpe_item.get('cpe', {})
                cpe_name = cpe.get('cpeName', '')
                
                if not cpe_name:
                    continue
                
                # Extract version from CPE name (component 5)
                cpe_parts = cpe_name.split(':')
                if len(cpe_parts) > 5:
                    version = cpe_parts[5]
                    
                    if self.debug_mode:
                        _logger.info("🔍 [DEBUG] Processing CPE %d: %s -> version: %s", idx, cpe_name, version)
                    
                    # Ensure parent hierarchy exists
                    parent_version_id = self._get_or_create_version_parent(version)
                    
                    # Check if product with this version already exists
                    existing = self.env['vuln.fw.nvd.cpe.product'].search([
                        ('vendor_id', '=', self.vendor_id.id),
                        ('name', '=', self.name),
                        ('version', '=', version)
                    ], limit=1)
                    
                    if existing:
                        # Version exists - check if parent needs to be updated
                        if existing.parent_id.id != parent_version_id:
                            _logger.info("🔄 Updating parent for existing version: %s v%s (old_parent: %s, new_parent: %s)", 
                                       self.name, version, existing.parent_id.id, parent_version_id)
                            existing.write({'parent_id': parent_version_id})
                            if self.debug_mode:
                                _logger.info("🔍 [DEBUG] Updated version %s parent from %s to %s", 
                                           version, existing.parent_id.id, parent_version_id)
                        else:
                            skipped_versions.append(version)
                            if self.debug_mode:
                                _logger.info("🔍 [DEBUG] Version %s already exists with correct parent, skipping", version)
                    else:
                        # Create new version product with hierarchical parent
                        try:
                            from datetime import datetime
                            # Extract NVD metadata
                            nvd_cpe_id = cpe.get('cpeNameId', '')
                            nvd_created_str = cpe.get('created', '')
                            nvd_last_modified_str = cpe.get('lastModified', '')
                            refs = cpe.get('refs', [])
                            deprecated_by = cpe.get('deprecatedBy', [])
                            
                            # Convert ISO timestamps to Odoo datetime format
                            nvd_created = None
                            nvd_last_modified = None
                            if nvd_created_str:
                                try:
                                    # Parse ISO format: 2019-06-20T01:31:51.500
                                    nvd_created = datetime.fromisoformat(nvd_created_str.replace('Z', '+00:00'))
                                except:
                                    pass
                            if nvd_last_modified_str:
                                try:
                                    nvd_last_modified = datetime.fromisoformat(nvd_last_modified_str.replace('Z', '+00:00'))
                                except:
                                    pass
                            
                            # Store references and deprecated_by as JSON
                            nvd_references_json = json.dumps(refs) if refs else ''
                            deprecated_by_json = json.dumps(deprecated_by) if deprecated_by else ''
                            
                            # Create or link reference records
                            reference_ids = []
                            if refs:
                                if self.debug_mode:
                                    _logger.info("🔗 [PRODUCT DEBUG] Processing %d references for version %s...", len(refs), version)
                                
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
                                            entity_type='product'
                                        )
                                        if reference:
                                            reference_ids.append(reference.id)
                                            
                                            # If this is a vendor reference, also link it to the vendor
                                            if mapped_type == 'vendor' and self.vendor_id:
                                                if self.vendor_id.id not in reference.cpe_vendor_ids.ids:
                                                    reference.write({'cpe_vendor_ids': [(4, self.vendor_id.id)]})
                                                    if self.debug_mode:
                                                        _logger.info("🔗 [PRODUCT DEBUG]   🏢 Linked vendor reference to: %s", 
                                                                   self.vendor_id.display_name)
                                            
                                            if self.debug_mode:
                                                _logger.info("🔗 [PRODUCT DEBUG]   ✅ Reference: %s (Type: %s)", 
                                                           ref_url[:80], mapped_type)
                            
                            new_product = self.create({
                                'vendor_id': self.vendor_id.id,
                                'name': self.name,
                                'version': version,
                                'cpe_part': self.cpe_part or 'a',
                                'category': self.category,
                                'parent_id': parent_version_id,
                                'title': cpe.get('titles', [{}])[0].get('title', ''),
                                'description': _('Auto-created from NVD API'),
                                'deprecated': cpe.get('deprecated', False),
                                'deprecated_by': deprecated_by_json,
                                'nvd_cpe_id': nvd_cpe_id,
                                'nvd_created': nvd_created,
                                'nvd_last_modified': nvd_last_modified,
                                'nvd_references': nvd_references_json,
                                'reference_ids': [(6, 0, reference_ids)] if reference_ids else False,
                            })
                            created_products.append(new_product)
                            _logger.info("✅ Created version product: %s v%s (ID: %s)", 
                                       self.name, version, new_product.id)
                            
                            if self.debug_mode:
                                _logger.info("🔍 [DEBUG] Created child product: %s v%s (parent: %s, child_id: %s)", 
                                            self.name, version, self.display_name, new_product.id)
                        except Exception as e:
                            _logger.error("❌ Failed to create version product %s v%s: %s", 
                                        self.name, version, str(e))
            
            # Summary log
            _logger.info("📊 Version product creation summary - Created: %d, Skipped: %d", 
                        len(created_products), len(skipped_versions))
            
            if created_products:
                message = _('Created %d version products from NVD API') % len(created_products)
                if skipped_versions:
                    message += _('\n(Skipped %d existing versions)') % len(skipped_versions)
                return {
                    'type': 'ir.actions.client',
                    'tag': 'display_notification',
                    'params': {
                        'title': _('Version Products Created'),
                        'message': message,
                        'type': 'success',
                        'sticky': True,
                    }
                }
            else:
                return {
                    'type': 'ir.actions.client',
                    'tag': 'display_notification',
                    'params': {
                        'title': _('No New Versions'),
                        'message': _('All version products already exist.'),
                        'type': 'info'
                    }
                }
                
        except Exception as e:
            _logger.error("Error creating version products: %s", str(e), exc_info=True)
            if self.debug_mode:
                _logger.error("🔍 [DEBUG] Exception details: %s", str(e), exc_info=True)
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Error'),
                    'message': _('Failed to create version products: %s') % str(e),
                    'type': 'error'
                }
            }
    
    # === HARDWARE-FIRMWARE RELATIONSHIP METHODS ===
    # NOTE: Firmware-hardware relationships should be detected from NVD CVE data,
    # not hardcoded. CVE configurations specify which firmware versions run on which hardware.
    # This will be implemented when CVE module is integrated.
    
    # === AUTO-BUILDING METHODS ===
    @api.onchange('vendor_id', 'name', 'category', 'version', 'cpe_update', 'cpe_edition', 
                  'cpe_language', 'cpe_sw_edition', 'cpe_target_sw', 'cpe_target_hw', 'cpe_other', 'cpe_part')
    def _onchange_cpe_components(self):
        """Auto-build CPE URI when key components change."""
        if self.vendor_id and self.name:
            self.cpe_uri = self._build_cpe_uri()
    
    @api.model_create_multi
    def create(self, vals_list):
        """Override create to auto-build CPE URI and trigger webhooks."""
        for vals in vals_list:
            if vals.get('vendor_id') and vals.get('name') and not vals.get('cpe_uri'):
                temp_record = self.env['vuln.fw.nvd.cpe.product'].new(vals)
                vals['cpe_uri'] = temp_record._build_cpe_uri()
                _logger.info("Auto-built CPE URI during creation: %s", vals['cpe_uri'])
        
        records = super(VulnFwNvdCpeProduct, self).create(vals_list)
        
        # Trigger outbound webhooks
        for record in records:
            webhooks = self.env['vuln.fw.nvd.cpe.webhook'].search([
                ('active', '=', True),
                ('webhook_type', '=', 'outbound')
            ])
            for webhook in webhooks:
                webhook._trigger_webhook(record, 'create')
        
        return records
    
    def write(self, vals):
        """Override write to auto-rebuild CPE URI when components change and trigger webhooks."""
        for record in self:
            component_fields = ['vendor_id', 'name', 'version', 'category', 'cpe_update', 
                              'cpe_edition', 'cpe_language', 'cpe_sw_edition', 'cpe_target_sw', 
                              'cpe_target_hw', 'cpe_other', 'cpe_part']
            if any(field in vals for field in component_fields) and not vals.get('cpe_uri'):
                new_cpe_uri = record._build_cpe_uri()
                if new_cpe_uri:
                    vals['cpe_uri'] = new_cpe_uri
                    _logger.info("Auto-rebuilt CPE URI during update: %s", new_cpe_uri)
        
        result = super(VulnFwNvdCpeProduct, self).write(vals)
        
        # Trigger outbound webhooks
        webhooks = self.env['vuln.fw.nvd.cpe.webhook'].search([
            ('active', '=', True),
            ('webhook_type', '=', 'outbound')
        ])
        for record in self:
            for webhook in webhooks:
                webhook._trigger_webhook(record, 'write')
        
        return result
    
    def toggle_debug_mode(self):
        """Toggle debug mode on/off."""
        self.debug_mode = not self.debug_mode
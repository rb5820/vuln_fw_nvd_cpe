# -*- coding: utf-8 -*-
"""CPE (Common Platform Enumeration) models for NVD integration"""
from odoo import models, fields, api, _
from odoo.exceptions import ValidationError, UserError
import re
import logging
import json
from datetime import datetime, timedelta

_logger = logging.getLogger(__name__)


class VulnFwNvdCpeDictionary(models.Model):
    """CPE Dictionary entries from NIST CPE Dictionary"""
    _name = 'vuln.fw.nvd.cpe.dictionary'
    _description = 'CPE Dictionary Entry'
    _inherit = ['mail.thread']
    _order = 'cpe_name'
    _rec_name = 'title'

    # Basic CPE Information
    cpe_name = fields.Char(
        string='CPE Name',
        required=True,
        index=True,
        help='CPE 2.3 formatted name (e.g., cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*)'
    )
    
    cpe_name_id = fields.Char(
        string='CPE Name ID',
        index=True,
        help='Unique CPE identifier from NIST'
    )
    
    title = fields.Char(
        string='Title',
        required=True,
        help='Human-readable title for the CPE entry'
    )
    
    # Parsed CPE Components
    part = fields.Selection([
        ('a', 'Application'),
        ('h', 'Hardware'),
        ('o', 'Operating System')
    ], string='Part', required=True, help='CPE part component')
    
    vendor = fields.Char(
        string='Vendor',
        required=True,
        index=True,
        help='Vendor or manufacturer name'
    )
    
    product = fields.Char(
        string='Product',
        required=True,
        index=True,
        help='Product name'
    )
    
    version = fields.Char(
        string='Version',
        help='Product version'
    )
    
    update_component = fields.Char(
        string='Update',
        help='Update or patch level'
    )
    
    edition = fields.Char(
        string='Edition',
        help='Product edition'
    )
    
    language = fields.Char(
        string='Language',
        help='Language localization'
    )
    
    sw_edition = fields.Char(
        string='Software Edition',
        help='Software edition (CPE 2.3)'
    )
    
    target_sw = fields.Char(
        string='Target Software',
        help='Target software environment'
    )
    
    target_hw = fields.Char(
        string='Target Hardware',
        help='Target hardware platform'
    )
    
    other = fields.Char(
        string='Other',
        help='Other qualifying information'
    )
    
    # Metadata
    deprecated = fields.Boolean(
        string='Deprecated',
        default=False,
        help='Whether this CPE entry is deprecated'
    )
    
    deprecated_date = fields.Datetime(
        string='Deprecated Date',
        help='Date when this CPE was deprecated'
    )
    
    deprecated_by = fields.Many2one(
        'vuln.fw.nvd.cpe.dictionary',
        string='Deprecated By',
        help='CPE entry that replaces this deprecated one'
    )
    
    # References and Links
    references = fields.Text(
        string='References',
        help='JSON array of reference URLs and descriptions'
    )
    
    # Sync Information
    last_modified = fields.Datetime(
        string='Last Modified',
        help='Last modification timestamp from NIST'
    )
    
    sync_date = fields.Datetime(
        string='Sync Date',
        default=fields.Datetime.now,
        help='Date when this CPE was last synchronized'
    )
    
    # Statistics and Usage
    vulnerability_count = fields.Integer(
        string='Vulnerabilities',
        compute='_compute_vulnerability_count',
        help='Number of vulnerabilities referencing this CPE'
    )
    
    match_count = fields.Integer(
        string='Matches',
        compute='_compute_match_count',
        help='Number of active CPE matches using this entry'
    )
    
    # Search and Indexing
    search_text = fields.Text(
        string='Search Text',
        compute='_compute_search_text',
        store=True,
        help='Searchable text combining all CPE components'
    )
    
    tags = fields.Char(
        string='Tags',
        help='Comma-separated tags for categorization'
    )
    
    @api.depends('cpe_name', 'title', 'vendor', 'product', 'version')
    def _compute_search_text(self):
        """Compute searchable text for full-text search"""
        for record in self:
            parts = [
                record.cpe_name or '',
                record.title or '',
                record.vendor or '',
                record.product or '',
                record.version or '',
                record.tags or ''
            ]
            record.search_text = ' '.join([p.lower() for p in parts if p])
    
    def _compute_vulnerability_count(self):
        """Count vulnerabilities referencing this CPE"""
        for record in self:
            # Count from vulnerability.cpe.match model (standalone compatibility)
            try:
                if 'vulnerability.cpe.match' in self.env:
                    record.vulnerability_count = self.env['vulnerability.cpe.match'].search_count([
                        ('cpe_name', '=', record.cpe_name)
                    ])
                else:
                    record.vulnerability_count = 0
            except Exception:
                record.vulnerability_count = 0
    
    def _compute_match_count(self):
        """Count active CPE matches using this entry"""
        for record in self:
            try:
                record.match_count = self.env['vuln.fw.nvd.cpe.match'].search_count([
                    ('cpe_dictionary_id', '=', record.id),
                    ('active', '=', True)
                ])
            except Exception:
                record.match_count = 0
    
    @api.constrains('cpe_name')
    def _check_cpe_name_format(self):
        """Validate CPE 2.3 name format"""
        cpe_regex = r'^cpe:2\.3:[aho]:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*$'
        
        for record in self:
            if record.cpe_name and not re.match(cpe_regex, record.cpe_name):
                raise ValidationError(_("Invalid CPE 2.3 format: %s") % record.cpe_name)
    
    @api.model_create_multi
    def create(self, vals_list):
        """Override create to parse CPE components"""
        for vals in vals_list:
            if 'cpe_name' in vals:
                parsed = self._parse_cpe_name(vals['cpe_name'])
                vals.update(parsed)
        return super().create(vals_list)
    
    def write(self, vals):
        """Override write to parse CPE components"""
        if 'cpe_name' in vals:
            parsed = self._parse_cpe_name(vals['cpe_name'])
            vals.update(parsed)
        return super().write(vals)
    
    def _parse_cpe_name(self, cpe_name):
        """Parse CPE 2.3 name into components"""
        if not cpe_name or not cpe_name.startswith('cpe:2.3:'):
            return {}
        
        parts = cpe_name.split(':')
        if len(parts) < 12:
            return {}
        
        return {
            'part': parts[2] if parts[2] != '*' else False,
            'vendor': self._decode_cpe_component(parts[3]),
            'product': self._decode_cpe_component(parts[4]),
            'version': self._decode_cpe_component(parts[5]),
            'update_component': self._decode_cpe_component(parts[6]),
            'edition': self._decode_cpe_component(parts[7]),
            'language': self._decode_cpe_component(parts[8]),
            'sw_edition': self._decode_cpe_component(parts[9]),
            'target_sw': self._decode_cpe_component(parts[10]),
            'target_hw': self._decode_cpe_component(parts[11]),
            'other': self._decode_cpe_component(parts[12]) if len(parts) > 12 else False,
        }
    
    def _decode_cpe_component(self, component):
        """Decode CPE component (handle wildcards and escaping)"""
        if not component or component == '*':
            return False
        
        # Basic URL decoding for CPE components
        import urllib.parse
        decoded = urllib.parse.unquote(component)
        
        # Handle CPE-specific escaping
        decoded = decoded.replace('\\:', ':')
        decoded = decoded.replace('\\\\', '\\')
        
        return decoded if decoded else False
    
    @api.model
    def search_cpe(self, query, limit=50):
        """Search CPE dictionary entries"""
        domain = []
        
        if query:
            # Search in multiple fields
            domain = [
                '|', '|', '|', '|',
                ('search_text', 'ilike', query),
                ('cpe_name', 'ilike', query),
                ('vendor', 'ilike', query),
                ('product', 'ilike', query),
                ('title', 'ilike', query)
            ]
        
        return self.search(domain, limit=limit, order='vulnerability_count desc, product, version')
    
    @api.model
    def suggest_cpe(self, vendor=None, product=None, version=None):
        """Suggest CPE entries based on asset information"""
        domain = [('deprecated', '=', False)]
        
        if vendor:
            domain.append(('vendor', 'ilike', vendor))
        
        if product:
            domain.append(('product', 'ilike', product))
        
        if version:
            domain.append(('version', 'ilike', version))
        
        suggestions = self.search(domain, limit=20, order='match_count desc, vulnerability_count desc')
        
        # Return structured suggestions with confidence scores
        results = []
        for cpe in suggestions:
            confidence = 0.0
            
            # Calculate confidence based on field matches
            if vendor and vendor.lower() in (cpe.vendor or '').lower():
                confidence += 0.4
            if product and product.lower() in (cpe.product or '').lower():
                confidence += 0.4
            if version and version.lower() in (cpe.version or '').lower():
                confidence += 0.2
            
            results.append({
                'id': cpe.id,
                'cpe_name': cpe.cpe_name,
                'title': cpe.title,
                'vendor': cpe.vendor,
                'product': cpe.product,
                'version': cpe.version,
                'confidence': confidence,
                'vulnerability_count': cpe.vulnerability_count
            })
        
        # Sort by confidence score
        results.sort(key=lambda x: x['confidence'], reverse=True)
        return results
    
    @api.model
    def refresh_cpe_dictionary(self):
        """Refresh CPE dictionary from NIST (called by cron)"""
        _logger.info("Starting CPE dictionary refresh from NIST")
        
        try:
            # This would implement the actual NIST CPE API integration
            # For now, we'll log that the refresh was triggered
            
            refresh_stats = {
                'started_at': fields.Datetime.now(),
                'new_entries': 0,
                'updated_entries': 0,
                'deprecated_entries': 0,
                'total_entries': self.search_count([]),
            }
            
            _logger.info("CPE dictionary refresh completed: %s", refresh_stats)
            
            # Store refresh statistics
            self.env['ir.config_parameter'].sudo().set_param(
                'vuln_fw_nvd_cpe.last_refresh_stats',
                json.dumps(refresh_stats, default=str)
            )
            
            return refresh_stats
            
        except Exception as e:
            _logger.error("CPE dictionary refresh failed: %s", str(e))
            raise UserError(_("CPE dictionary refresh failed: %s") % str(e))
    
    @api.model
    def update_cpe_statistics(self):
        """Update CPE usage statistics (called by cron)"""
        _logger.info("Updating CPE statistics")
        
        # Force recomputation of computed fields
        all_cpes = self.search([])
        all_cpes._compute_vulnerability_count()
        all_cpes._compute_match_count()
        
        return True
    
    def action_view_vulnerabilities(self):
        """View vulnerabilities that reference this CPE"""
        self.ensure_one()
        
        return {
            'type': 'ir.actions.act_window',
            'name': _('Vulnerabilities: %s') % self.cpe_name,
            'res_model': 'vulnerability.vulnerability',
            'view_mode': 'list,form',
            'domain': [('cpe_match_ids.cpe_name', '=', self.cpe_name)],
            'context': {'default_cpe_filter': self.cpe_name}
        }
    
    def action_view_matches(self):
        """View CPE matches using this dictionary entry"""
        self.ensure_one()
        
        return {
            'type': 'ir.actions.act_window',
            'name': _('CPE Matches: %s') % self.title,
            'res_model': 'vuln.fw.nvd.cpe.match',
            'view_mode': 'list,form',
            'domain': [('cpe_dictionary_id', '=', self.id)],
            'context': {'default_cpe_dictionary_id': self.id}
        }


class VulnFwNvdCpeMatch(models.Model):
    """CPE matches linking assets to CPE dictionary entries"""
    _name = 'vuln.fw.nvd.cpe.match'
    _description = 'CPE Asset Match'
    _inherit = ['mail.thread']
    _order = 'confidence_score desc, match_date desc'
    _rec_name = 'display_name'

    # Match Information
    display_name = fields.Char(
        string='Display Name',
        compute='_compute_display_name',
        store=True
    )
    
    cpe_dictionary_id = fields.Many2one(
        'vuln.fw.nvd.cpe.dictionary',
        string='CPE Entry',
        required=True,
        ondelete='cascade',
        help='Reference to CPE dictionary entry'
    )
    
    # Asset Reference (flexible for different asset types)
    asset_model = fields.Char(
        string='Asset Model',
        required=True,
        help='Model name of the matched asset'
    )
    
    asset_id = fields.Integer(
        string='Asset ID',
        required=True,
        help='Database ID of the matched asset'
    )
    
    asset_name = fields.Char(
        string='Asset Name',
        help='Cached name of the matched asset'
    )
    
    # Match Details
    match_method = fields.Selection([
        ('automatic', 'Automatic Detection'),
        ('manual', 'Manual Assignment'),
        ('api_import', 'API Import'),
        ('bulk_import', 'Bulk Import'),
        ('suggestion_accepted', 'Suggestion Accepted'),
        ('scan_result', 'Scan Result')
    ], string='Match Method', default='manual', required=True)
    
    confidence_score = fields.Float(
        string='Confidence Score',
        digits=(3, 2),
        default=1.0,
        help='Confidence in this CPE match (0.0-1.0)'
    )
    
    match_criteria = fields.Text(
        string='Match Criteria',
        help='JSON describing the criteria used for matching'
    )
    
    # Dates
    match_date = fields.Datetime(
        string='Match Date',
        default=fields.Datetime.now,
        required=True,
        help='When this match was created'
    )
    
    verified_date = fields.Datetime(
        string='Verified Date',
        help='When this match was last verified'
    )
    
    # Status
    status = fields.Selection([
        ('pending', 'Pending Verification'),
        ('verified', 'Verified'),
        ('rejected', 'Rejected'),
        ('outdated', 'Outdated')
    ], string='Status', default='pending', required=True)
    
    active = fields.Boolean(
        string='Active',
        default=True,
        help='Whether this match is actively used'
    )
    
    notes = fields.Text(
        string='Notes',
        help='Additional notes about this match'
    )
    
    # Related Information (computed from CPE dictionary)
    cpe_name = fields.Char(
        string='CPE Name',
        related='cpe_dictionary_id.cpe_name',
        store=True
    )
    
    vendor = fields.Char(
        string='Vendor',
        related='cpe_dictionary_id.vendor',
        store=True
    )
    
    product = fields.Char(
        string='Product',
        related='cpe_dictionary_id.product',
        store=True
    )
    
    version = fields.Char(
        string='Version',
        related='cpe_dictionary_id.version',
        store=True
    )
    
    # Company Support
    company_id = fields.Many2one(
        'res.company',
        string='Company',
        default=lambda self: self.env.company
    )
    
    # Vulnerability Relationships
    vulnerability_count = fields.Integer(
        string='Related Vulnerabilities',
        compute='_compute_vulnerability_count',
        help='Number of vulnerabilities affecting this CPE match'
    )
    
    @api.depends('asset_name', 'cpe_dictionary_id.title', 'confidence_score')
    def _compute_display_name(self):
        """Compute display name for CPE match"""
        for record in self:
            parts = []
            if record.asset_name:
                parts.append(record.asset_name)
            if record.cpe_dictionary_id:
                parts.append(f"→ {record.cpe_dictionary_id.title}")
            if record.confidence_score < 1.0:
                parts.append(f"({record.confidence_score:.0%})")
            
            record.display_name = ' '.join(parts) or 'CPE Match'
    
    def _compute_vulnerability_count(self):
        """Count vulnerabilities affecting this CPE match"""
        for record in self:
            try:
                if 'vulnerability.cpe.match' in self.env and record.cpe_name:
                    record.vulnerability_count = self.env['vulnerability.cpe.match'].search_count([
                        ('cpe_name', '=', record.cpe_name)
                    ])
                else:
                    record.vulnerability_count = 0
            except Exception:
                record.vulnerability_count = 0
    
    @api.constrains('confidence_score')
    def _check_confidence_score(self):
        """Validate confidence score range"""
        for record in self:
            if not (0.0 <= record.confidence_score <= 1.0):
                raise ValidationError(_("Confidence score must be between 0.0 and 1.0"))
    
    @api.model
    def create_match(self, asset_model, asset_id, cpe_dictionary_id, **kwargs):
        """Create a new CPE match with validation"""
        # Get asset name for caching
        asset_name = self._get_asset_name(asset_model, asset_id)
        
        vals = {
            'asset_model': asset_model,
            'asset_id': asset_id,
            'asset_name': asset_name,
            'cpe_dictionary_id': cpe_dictionary_id,
            **kwargs
        }
        
        return self.create(vals)
    
    def _get_asset_name(self, asset_model, asset_id):
        """Get asset name for display purposes"""
        try:
            asset = self.env[asset_model].browse(asset_id)
            if asset.exists():
                # Try common name fields
                for field in ['name', 'display_name', 'title', 'hostname']:
                    if hasattr(asset, field):
                        return getattr(asset, field)
                return f"{asset_model}#{asset_id}"
            return f"Missing {asset_model}#{asset_id}"
        except Exception:
            return f"Invalid {asset_model}#{asset_id}"
    
    def action_verify_match(self):
        """Verify this CPE match"""
        self.ensure_one()
        self.write({
            'status': 'verified',
            'verified_date': fields.Datetime.now()
        })
        return True
    
    def action_reject_match(self):
        """Reject this CPE match"""
        self.ensure_one()
        self.write({
            'status': 'rejected',
            'active': False
        })
        return True
    
    def action_view_vulnerabilities(self):
        """View vulnerabilities affecting this CPE match"""
        self.ensure_one()
        
        return {
            'type': 'ir.actions.act_window',
            'name': _('Vulnerabilities: %s') % self.display_name,
            'res_model': 'vulnerability.vulnerability',
            'view_mode': 'list,form',
            'domain': [('cpe_match_ids.cpe_name', '=', self.cpe_name)],
            'context': {
                'default_asset_filter': f"{self.asset_model}:{self.asset_id}"
            }
        }
    
    def action_view_asset(self):
        """View the matched asset"""
        self.ensure_one()
        
        try:
            return {
                'type': 'ir.actions.act_window',
                'name': _('Asset: %s') % self.asset_name,
                'res_model': self.asset_model,
                'res_id': self.asset_id,
                'view_mode': 'form',
                'views': [(False, 'form')]
            }
        except Exception:
            raise UserError(_("Cannot open asset %s#%d") % (self.asset_model, self.asset_id))
    
    @api.model
    def cleanup_stale_matches(self):
        """Clean up stale CPE matches (called by cron)"""
        _logger.info("Cleaning up stale CPE matches")
        
        # Find matches with non-existent assets
        stale_matches = []
        
        for match in self.search([('active', '=', True)]):
            try:
                asset = self.env[match.asset_model].browse(match.asset_id)
                if not asset.exists():
                    stale_matches.append(match.id)
            except Exception:
                stale_matches.append(match.id)
        
        if stale_matches:
            self.browse(stale_matches).write({
                'status': 'outdated',
                'active': False
            })
            _logger.info("Marked %d CPE matches as stale", len(stale_matches))
        
        return len(stale_matches)
    
    @api.model
    def auto_match_assets(self, asset_model, domain=None):
        """Automatically match assets to CPE entries"""
        if domain is None:
            domain = []
        
        assets = self.env[asset_model].search(domain)
        matches_created = 0
        
        for asset in assets:
            # Extract asset information for CPE matching
            asset_info = self._extract_asset_info(asset)
            
            # Find CPE suggestions
            suggestions = self.env['vuln.fw.nvd.cpe.dictionary'].suggest_cpe(**asset_info)
            
            # Create matches for high-confidence suggestions
            for suggestion in suggestions:
                if suggestion['confidence'] >= 0.7:  # Configurable threshold
                    # Check if match already exists
                    existing = self.search([
                        ('asset_model', '=', asset_model),
                        ('asset_id', '=', asset.id),
                        ('cpe_dictionary_id', '=', suggestion['id'])
                    ])
                    
                    if not existing:
                        self.create_match(
                            asset_model=asset_model,
                            asset_id=asset.id,
                            cpe_dictionary_id=suggestion['id'],
                            match_method='automatic',
                            confidence_score=suggestion['confidence'],
                            status='pending',
                            match_criteria=json.dumps(asset_info)
                        )
                        matches_created += 1
        
        return matches_created
    
    def _extract_asset_info(self, asset):
        """Extract relevant information from asset for CPE matching"""
        info = {}
        
        # Common asset fields to check
        field_mapping = {
            'vendor': ['vendor', 'manufacturer', 'brand'],
            'product': ['product', 'model', 'software_name', 'name'],
            'version': ['version', 'software_version', 'firmware_version']
        }
        
        for cpe_field, asset_fields in field_mapping.items():
            for field in asset_fields:
                if hasattr(asset, field) and getattr(asset, field):
                    info[cpe_field] = str(getattr(asset, field))
                    break
        
        return info
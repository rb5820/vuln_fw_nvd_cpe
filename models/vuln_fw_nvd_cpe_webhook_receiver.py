# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
import logging
import json

_logger = logging.getLogger(__name__)


class VulnFwNvdCpeWebhookReceiver(models.Model):
    """
    CPE-specific Webhook Receiver Extension.
    Extends base receiver with CPE product auto-creation and update logic.
    """
    _name = 'vuln.fw.nvd.cpe.webhook.receiver'
    _description = 'CPE Webhook Receiver'
    _inherit = 'vuln.fw.nvd.webhook.receiver'
    
    # === CPE-SPECIFIC PROCESSING ===
    
    auto_create_products = fields.Boolean(
        string='Auto Create Products',
        default=True,
        help='Automatically create CPE products from webhook data'
    )
    
    auto_update_products = fields.Boolean(
        string='Auto Update Products',
        default=True,
        help='Automatically update CPE products from webhook data'
    )
    
    update_field_list = fields.Text(
        string='Fields to Update (JSON)',
        default='["name", "version", "deprecated", "nvd_cpe_id"]',
        help='JSON array of field names to update when receiving webhook'
    )
    
    match_by_cpe_uri = fields.Boolean(
        string='Match by CPE URI',
        default=True,
        help='Match existing products by CPE URI before creating new ones'
    )
    
    # === VENDOR MAPPING ===
    
    default_vendor_id = fields.Many2one(
        'vuln.fw.nvd.cpe.vendor',
        string='Default Vendor',
        help='Default vendor for products created from webhooks'
    )
    
    vendor_mapping = fields.Text(
        string='Vendor Name Mapping (JSON)',
        help='JSON mapping of external vendor names to Odoo vendor IDs'
    )
    
    # === METHODS ===
    
    def _process_payload(self, payload):
        """
        Process CPE webhook payload.
        Creates or updates CPE products based on webhook data.
        """
        if not isinstance(payload, dict):
            _logger.warning("Invalid payload format: %s", type(payload))
            return None
        
        created_ids = []
        
        # Handle single product or batch
        if 'products' in payload:
            # Batch mode
            for product_data in payload['products']:
                product_id = self._process_product_data(product_data)
                if product_id:
                    created_ids.append(product_id)
        else:
            # Single product mode
            product_id = self._process_product_data(payload)
            if product_id:
                created_ids.append(product_id)
        
        _logger.info("✅ Processed %d products from webhook", len(created_ids))
        return created_ids
    
    def _process_product_data(self, product_data):
        """
        Process a single product from webhook data.
        
        Args:
            product_data (dict): Product information from webhook
            
        Returns:
            int: Created or updated product ID, or None
        """
        if not isinstance(product_data, dict):
            _logger.warning("Invalid product data format: %s", type(product_data))
            return None
        
        # Extract vendor
        vendor_name = product_data.get('vendor_name') or product_data.get('vendor')
        if not vendor_name and self.default_vendor_id:
            vendor_id = self.default_vendor_id.id
        elif vendor_name:
            # Try to find vendor
            vendor = self.env['vuln.fw.nvd.cpe.vendor'].search([
                ('name', '=', vendor_name)
            ], limit=1)
            
            if vendor:
                vendor_id = vendor.id
            else:
                # Try vendor mapping
                mapping = {}
                try:
                    mapping = json.loads(self.vendor_mapping or '{}')
                except json.JSONDecodeError:
                    _logger.warning("Invalid vendor mapping JSON")
                
                if vendor_name in mapping:
                    vendor_id = mapping[vendor_name]
                else:
                    # Use default vendor
                    if self.default_vendor_id:
                        vendor_id = self.default_vendor_id.id
                    else:
                        _logger.warning("Could not find vendor: %s", vendor_name)
                        return None
        else:
            return None
        
        # Extract CPE URI if provided
        cpe_uri = product_data.get('cpe_uri')
        
        # Search for existing product
        existing_product = None
        if cpe_uri and self.match_by_cpe_uri:
            existing_product = self.env['vuln.fw.nvd.cpe.product'].search([
                ('cpe_uri', '=', cpe_uri)
            ], limit=1)
        
        # Prepare product data
        product_vals = {
            'vendor_id': vendor_id,
            'name': product_data.get('name'),
            'version': product_data.get('version', ''),
        }
        
        # Add optional fields
        if 'cpe_part' in product_data:
            product_vals['cpe_part'] = product_data['cpe_part']
        if 'category' in product_data:
            product_vals['category'] = product_data['category']
        if 'deprecated' in product_data:
            product_vals['deprecated'] = product_data['deprecated']
        if 'nvd_cpe_id' in product_data:
            product_vals['nvd_cpe_id'] = product_data['nvd_cpe_id']
        if 'description' in product_data:
            product_vals['description'] = product_data['description']
        
        # Create or update product
        if existing_product and self.auto_update_products:
            # Update only allowed fields
            update_fields = []
            try:
                update_fields = json.loads(self.update_field_list or '[]')
            except json.JSONDecodeError:
                _logger.warning("Invalid update field list JSON")
            
            update_vals = {k: v for k, v in product_vals.items() if k in update_fields}
            if update_vals:
                existing_product.write(update_vals)
            return existing_product.id
        elif not existing_product and self.auto_create_products:
            new_product = self.env['vuln.fw.nvd.cpe.product'].create(product_vals)
            return new_product.id
        
        return None


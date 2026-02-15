# -*- coding: utf-8 -*-

from odoo import models, fields, api
import logging
import json
from datetime import datetime

_logger = logging.getLogger(__name__)


class VulnFwNvdCpeWebhook(models.Model):
    """
    CPE-specific Webhook Extension.
    Extends the base webhook with CPE product-specific payload building.
    """
    _name = 'vuln.fw.nvd.cpe.webhook'
    _description = 'CPE Webhook Configuration'
    _inherit = 'vuln.fw.nvd.webhook'
    
    # === CPE-SPECIFIC PAYLOAD OPTIONS ===
    
    include_full_product = fields.Boolean(
        string='Include Full Product Data',
        default=True,
        help='Include complete CPE product information in webhook payload'
    )
    
    include_cpe_uri = fields.Boolean(
        string='Include CPE URI',
        default=True,
        help='Include CPE URI in webhook payload'
    )
    
    include_parent_child = fields.Boolean(
        string='Include Parent-Child Relationships',
        default=True,
        help='Include parent_id and child_ids in webhook payload'
    )
    
    include_metadata = fields.Boolean(
        string='Include NVD Metadata',
        default=True,
        help='Include NVD metadata (timestamps, IDs, references)'
    )
    
    payload_template = fields.Text(
        string='Custom Payload Template (JSON)',
        help='Custom payload template. Use {product_id}, {product_name}, {cpe_uri}, etc.'
    )
    
    # === METHODS ===
    
    def _build_payload(self, product, event_type):
        """
        Build CPE-specific webhook payload from product.
        Overrides base method to include CPE-specific fields.
        """
        payload = {
            'event': event_type,
            'timestamp': datetime.now().isoformat(),
            'webhook_id': self.id,
            'product_id': product.id,
        }
        
        if self.include_full_product:
            payload['product'] = {
                'id': product.id,
                'name': product.name,
                'version': product.version,
                'vendor_id': product.vendor_id.id,
                'vendor_name': product.vendor_id.name,
                'category': product.category,
                'cpe_part': product.cpe_part,
                'display_name': product.display_name,
                'title': product.title,
                'description': product.description,
            }
        
        if self.include_cpe_uri:
            payload['cpe_uri'] = product.cpe_uri
        
        if self.include_parent_child:
            payload['parent_id'] = product.parent_id.id if product.parent_id else None
            payload['child_ids'] = [c.id for c in product.child_ids]
            payload['version_level'] = product.version_level
        
        if self.include_metadata:
            payload['metadata'] = {
                'nvd_cpe_id': product.nvd_cpe_id,
                'nvd_created': product.nvd_created.isoformat() if product.nvd_created else None,
                'nvd_last_modified': product.nvd_last_modified.isoformat() if product.nvd_last_modified else None,
                'deprecated': product.deprecated,
            }
        
        return payload


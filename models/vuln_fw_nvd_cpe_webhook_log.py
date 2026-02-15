# -*- coding: utf-8 -*-

from odoo import models, fields
import logging

_logger = logging.getLogger(__name__)


class VulnFwNvdCpeWebhookLog(models.Model):
    """
    CPE Webhook Log Extension - Adds product_id tracking.
    """
    _name = 'vuln.fw.nvd.cpe.webhook.log'
    _description = 'CPE Webhook Log'
    _inherit = 'vuln.fw.nvd.webhook.log'
    
    # === CPE-SPECIFIC RELATIONSHIPS ===
    
    product_id = fields.Many2one(
        'vuln.fw.nvd.cpe.product',
        string='CPE Product',
        help='The product that triggered the webhook'
    )

    
    # === DISPLAY ===
    
    def name_get(self):
        """Custom display name for log entries."""
        result = []
        for record in self:
            name = f"{record.webhook_id.name} - {record.event_type} ({record.status})"
            if record.product_id:
                name += f" - {record.product_id.display_name}"
            result.append((record.id, name))
        return result

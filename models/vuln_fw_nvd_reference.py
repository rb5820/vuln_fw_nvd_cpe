# -*- coding: utf-8 -*-

from odoo import api, fields, models
import logging

_logger = logging.getLogger(__name__)


class VulnFwNvdReference(models.Model):
    """
    Extend base reference model with CPE-specific relationships.
    """
    _inherit = 'vuln.fw.nvd.reference'
    
    # === CPE RELATIONSHIPS ===
    cpe_product_ids = fields.Many2many(
        comodel_name='vuln.fw.nvd.cpe.product',
        relation='vuln_fw_nvd_ref_cpe_product_rel',
        column1='reference_id',
        column2='product_id',
        string='CPE Products',
        help='CPE products that reference this URL'
    )
    
    cpe_vendor_ids = fields.Many2many(
        comodel_name='vuln.fw.nvd.cpe.vendor',
        relation='vuln_fw_nvd_ref_cpe_vendor_rel',
        column1='reference_id',
        column2='vendor_id',
        string='CPE Vendors',
        help='CPE vendors that reference this URL'
    )
    
    @api.depends('cpe_product_ids', 'cpe_vendor_ids')
    def _compute_usage_count(self):
        """
        Override to count CPE product and vendor linkages.
        """
        for record in self:
            cpe_count = len(record.cpe_product_ids) + len(record.cpe_vendor_ids)
            # Call super to get count from other modules (e.g., CVE)
            super(VulnFwNvdReference, record)._compute_usage_count()
            # Add CPE count to existing count
            record.usage_count += cpe_count
    
    def action_view_cpe_products(self):
        """View CPE products linked to this reference."""
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': 'CPE Products',
            'res_model': 'vuln.fw.nvd.cpe.product',
            'view_mode': 'list,form',
            'domain': [('id', 'in', self.cpe_product_ids.ids)],
            'context': {'default_reference_ids': [(6, 0, [self.id])]}
        }
    
    def action_view_cpe_vendors(self):
        """View CPE vendors linked to this reference."""
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': 'CPE Vendors',
            'res_model': 'vuln.fw.nvd.cpe.vendor',
            'view_mode': 'list,form',
            'domain': [('id', 'in', self.cpe_vendor_ids.ids)],
            'context': {'default_reference_ids': [(6, 0, [self.id])]}
        }

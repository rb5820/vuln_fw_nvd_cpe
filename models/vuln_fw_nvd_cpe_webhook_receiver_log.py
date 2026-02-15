# -*- coding: utf-8 -*-

from odoo import models


class VulnFwNvdCpeWebhookReceiverLog(models.Model):
    """
    CPE Webhook Receiver Log Extension.
    Uses base model without additional customizations.
    """
    _name = 'vuln.fw.nvd.cpe.webhook.receiver.log'
    _description = 'CPE Webhook Receiver Log'
    _inherit = 'vuln.fw.nvd.webhook.receiver.log'

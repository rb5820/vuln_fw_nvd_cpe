# -*- coding: utf-8 -*-

from odoo import http
from odoo.http import request
import json
import logging

_logger = logging.getLogger(__name__)


class CpeWebhookReceiver(http.Controller):
    """
    HTTP Controller for handling inbound CPE webhooks.
    """
    
    @http.route(
        '/cpe/webhook/<string:token>',
        type='json',
        auth='public',
        methods=['POST'],
        csrf=False,
        cors='*'
    )
    def receive_webhook(self, token, **kwargs):
        """
        Receive and process CPE webhook.
        
        Args:
            token (str): Webhook receiver token for authentication
            
        Returns:
            dict: Response with status and message
        """
        try:
            # Get the webhook receiver by token
            receiver = request.env['vuln.fw.nvd.cpe.webhook.receiver'].sudo().search([
                ('webhook_token', '=', token),
                ('active', '=', True)
            ], limit=1)
            
            if not receiver:
                _logger.warning("❌ Webhook received with invalid token: %s", token)
                return {
                    'status': 'error',
                    'message': 'Invalid webhook token',
                    'code': 401
                }
            
            # Get source IP
            source_ip = request.httprequest.remote_addr
            
            # Get payload
            payload = request.get_json_data()
            
            # Get signature from header
            signature = request.httprequest.headers.get('X-Webhook-Signature')
            
            _logger.info("📥 Webhook received from %s for receiver: %s", source_ip, receiver.name)
            
            # Process webhook
            success, message, created_ids = receiver.process_webhook(
                payload,
                source_ip=source_ip,
                signature=signature
            )
            
            return {
                'status': 'success' if success else 'error',
                'message': message,
                'created_product_ids': created_ids,
            }
            
        except Exception as e:
            _logger.error("❌ Webhook processing error: %s", str(e), exc_info=True)
            return {
                'status': 'error',
                'message': f'Processing error: {str(e)}',
                'code': 500
            }
    
    @http.route(
        '/cpe/webhook/test/<string:token>',
        type='json',
        auth='public',
        methods=['GET'],
        csrf=False,
        cors='*'
    )
    def test_webhook(self, token, **kwargs):
        """
        Test webhook receiver endpoint.
        
        Args:
            token (str): Webhook receiver token
            
        Returns:
            dict: Test response
        """
        try:
            receiver = request.env['vuln.fw.nvd.cpe.webhook.receiver'].sudo().search([
                ('webhook_token', '=', token),
                ('active', '=', True)
            ], limit=1)
            
            if not receiver:
                return {
                    'status': 'error',
                    'message': 'Invalid webhook token',
                    'code': 401
                }
            
            return {
                'status': 'success',
                'message': f'Webhook receiver "{receiver.name}" is active and accepting requests',
                'receiver_id': receiver.id,
                'receiver_name': receiver.name,
            }
            
        except Exception as e:
            _logger.error("❌ Webhook test error: %s", str(e))
            return {
                'status': 'error',
                'message': f'Error: {str(e)}',
                'code': 500
            }

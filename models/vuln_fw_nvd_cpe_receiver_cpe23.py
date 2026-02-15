# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
import logging
import json
import re

_logger = logging.getLogger(__name__)


class VulnFwNvdCpeReceiverCpe23(models.Model):
    """
    CPE 2.3 Specialized Webhook Receiver.
    Optimized for receiving and processing full CPE 2.3 entries.
    Parses CPE 2.3 formatted names and creates/updates CPE dictionary entries.
    """
    _name = 'vuln.fw.nvd.cpe.receiver.cpe23'
    _description = 'CPE 2.3 Webhook Receiver'
    _inherit = 'vuln.fw.nvd.webhook.receiver'
    
    # === CPE2.3 SPECIFIC SETTINGS ===
    
    parse_cpe_name = fields.Boolean(
        string='Parse CPE Name',
        default=True,
        help='Automatically parse CPE 2.3 formatted names into components'
    )
    
    auto_create_dictionary = fields.Boolean(
        string='Auto Create Dictionary',
        default=True,
        help='Automatically create CPE dictionary entries from webhook data'
    )
    
    auto_update_dictionary = fields.Boolean(
        string='Auto Update Dictionary',
        default=True,
        help='Automatically update existing CPE dictionary entries'
    )
    
    merge_with_existing = fields.Boolean(
        string='Merge with Existing',
        default=True,
        help='Merge new data with existing CPE dictionary entries'
    )
    
    create_missing_vendors = fields.Boolean(
        string='Create Missing Vendors',
        default=True,
        help='Create vendor records if they do not exist'
    )
    
    # === BATCH PROCESSING ===
    
    batch_size = fields.Integer(
        string='Batch Size',
        default=100,
        help='Number of CPE entries to process per batch'
    )
    
    skip_deprecated = fields.Boolean(
        string='Skip Deprecated',
        default=False,
        help='Skip processing of deprecated CPE entries'
    )
    
    # === FIELD MAPPING ===
    
    cpe_field_mapping = fields.Text(
        string='CPE Field Mapping (JSON)',
        default='{"cpe_name": "cpe_name", "title": "title", "references": "references", "deprecated": "deprecated"}',
        help='JSON mapping of webhook fields to CPE dictionary fields'
    )
    
    # === METHODS ===
    
    def _process_payload(self, payload):
        """
        Process CPE 2.3 webhook payload.
        Expects either a single CPE entry or a batch of CPE entries.
        """
        if not isinstance(payload, dict):
            _logger.warning("Invalid CPE 2.3 payload format: %s", type(payload))
            return None
        
        created_ids = []
        updated_ids = []
        
        try:
            # Handle batch or single entry
            cpe_entries = []
            if 'cpe_entries' in payload:
                cpe_entries = payload['cpe_entries']
            elif 'entries' in payload:
                cpe_entries = payload['entries']
            elif 'cpe_name' in payload:
                # Single CPE entry
                cpe_entries = [payload]
            
            if not cpe_entries:
                _logger.warning("No CPE entries found in payload")
                return None
            
            # Process each CPE entry
            for idx, cpe_data in enumerate(cpe_entries):
                if idx % self.batch_size == 0:
                    _logger.info("Processing CPE batch: %d-%d", idx, min(idx + self.batch_size, len(cpe_entries)))
                
                try:
                    result = self._process_cpe_entry(cpe_data)
                    if result.get('action') == 'create':
                        created_ids.append(result['id'])
                    elif result.get('action') == 'update':
                        updated_ids.append(result['id'])
                except Exception as e:
                    _logger.error("Error processing CPE entry: %s", str(e))
                    continue
            
            return {
                'created': len(created_ids),
                'updated': len(updated_ids),
                'total': len(cpe_entries),
                'created_ids': created_ids,
                'updated_ids': updated_ids
            }
        
        except Exception as e:
            _logger.error("Error processing CPE 2.3 payload: %s", str(e))
            raise
    
    def _process_cpe_entry(self, cpe_data):
        """Process a single CPE 2.3 entry"""
        
        if self.skip_deprecated and cpe_data.get('deprecated'):
            _logger.info("Skipping deprecated CPE: %s", cpe_data.get('cpe_name'))
            return {'action': 'skip'}
        
        cpe_name = cpe_data.get('cpe_name')
        if not cpe_name:
            raise ValueError("Missing cpe_name field")
        
        # Parse CPE name if enabled
        parsed_data = cpe_data.copy()
        if self.parse_cpe_name:
            parsed_data.update(self._parse_cpe_name(cpe_name))
        
        # Get field mapping
        field_mapping = self._get_field_mapping()
        
        # Prepare dictionary data
        dictionary_data = {}
        for webhook_field, model_field in field_mapping.items():
            if webhook_field in parsed_data:
                dictionary_data[model_field] = parsed_data[webhook_field]
        
        # Ensure required fields
        if 'cpe_name' not in dictionary_data:
            dictionary_data['cpe_name'] = cpe_name
        if 'title' not in dictionary_data:
            dictionary_data['title'] = parsed_data.get('title', cpe_name)
        if 'part' not in dictionary_data:
            dictionary_data['part'] = parsed_data.get('part', 'a')
        if 'vendor' not in dictionary_data:
            dictionary_data['vendor'] = parsed_data.get('vendor', 'unknown')
        if 'product' not in dictionary_data:
            dictionary_data['product'] = parsed_data.get('product', 'unknown')
        
        # Check if vendor exists, create if needed
        if self.create_missing_vendors and dictionary_data.get('vendor'):
            self._ensure_vendor_exists(dictionary_data['vendor'])
        
        # Find or create CPE dictionary entry
        existing = self.env['vuln.fw.nvd.cpe.dictionary'].search([
            ('cpe_name', '=', cpe_name)
        ], limit=1)
        
        if existing:
            if self.auto_update_dictionary and self.merge_with_existing:
                # Merge data: keep existing values, update only specified fields
                for key, value in dictionary_data.items():
                    if value and (not hasattr(existing, key) or not getattr(existing, key)):
                        existing[key] = value
                existing.flush()
            return {'action': 'update', 'id': existing.id}
        else:
            if self.auto_create_dictionary:
                new_entry = self.env['vuln.fw.nvd.cpe.dictionary'].create(dictionary_data)
                return {'action': 'create', 'id': new_entry.id}
            else:
                return {'action': 'skip'}
    
    def _parse_cpe_name(self, cpe_name):
        """
        Parse CPE 2.3 formatted name: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
        Returns dict with parsed components
        """
        result = {
            'part': 'a',
            'vendor': 'unknown',
            'product': 'unknown',
            'version': '*',
            'update': '*',
            'edition': '*',
            'language': '*'
        }
        
        try:
            # Remove cpe:2.3: prefix
            if cpe_name.startswith('cpe:2.3:'):
                parts = cpe_name[8:].split(':')
            else:
                parts = cpe_name.split(':')
            
            if len(parts) >= 1:
                result['part'] = parts[0] if parts[0] in ['a', 'h', 'o'] else 'a'
            if len(parts) >= 2:
                result['vendor'] = parts[1] if parts[1] != '*' else 'unknown'
            if len(parts) >= 3:
                result['product'] = parts[2] if parts[2] != '*' else 'unknown'
            if len(parts) >= 4:
                result['version'] = parts[3]
            if len(parts) >= 5:
                result['update'] = parts[4]
            if len(parts) >= 6:
                result['edition'] = parts[5]
            if len(parts) >= 7:
                result['language'] = parts[6]
        
        except Exception as e:
            _logger.warning("Error parsing CPE name %s: %s", cpe_name, str(e))
        
        return result
    
    def _get_field_mapping(self):
        """Get field mapping from JSON config"""
        try:
            return json.loads(self.cpe_field_mapping or '{}')
        except json.JSONDecodeError:
            _logger.warning("Invalid JSON in cpe_field_mapping")
            return {}
    
    def _ensure_vendor_exists(self, vendor_name):
        """Ensure vendor exists, create if needed using unified method"""
        if not vendor_name or vendor_name == 'unknown':
            return None
        
        # Use unified get_or_create method
        # For webhooks, we don't have an API key, so just search locally and create manually if needed
        vendor = self.env['vuln.fw.nvd.cpe.vendor'].search([
            ('name', '=ilike', vendor_name)
        ], limit=1)
        
        if not vendor:
            vendor = self.env['vuln.fw.nvd.cpe.vendor'].create({
                'name': vendor_name,
                'description': 'Created from webhook import',
                'active': True
            })
            _logger.info("Created new vendor from webhook: %s", vendor_name)
        
        return vendor

# -*- coding: utf-8 -*-
"""Helper services for CPE (Common Platform Enumeration) operations"""
from odoo import models, api, _
from odoo.exceptions import ValidationError, UserError
import re
import logging
import urllib.parse
import json
from difflib import SequenceMatcher

_logger = logging.getLogger(__name__)


class CpeValidationService(models.AbstractModel):
    """Service for CPE validation and normalization"""
    _name = 'vuln.fw.nvd.cpe.validation.service'
    _description = 'CPE Validation Service'

    @api.model
    def validate_cpe_name(self, cpe_name):
        """Validate CPE 2.3 name format"""
        if not cpe_name:
            return False, _("CPE name cannot be empty")
        
        # CPE 2.3 format regex
        cpe_regex = r'^cpe:2\.3:[aho\*]:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*$'
        
        if not re.match(cpe_regex, cpe_name):
            return False, _("Invalid CPE 2.3 format")
        
        parts = cpe_name.split(':')
        if len(parts) < 12:
            return False, _("Insufficient CPE components")
        
        # Validate part component
        if parts[2] not in ['a', 'h', 'o', '*']:
            return False, _("Invalid part component: must be 'a', 'h', 'o', or '*'")
        
        # Validate that vendor and product are not wildcards if part is specified
        if parts[2] != '*':
            if parts[3] == '*':
                return False, _("Vendor cannot be wildcard when part is specified")
            if parts[4] == '*':
                return False, _("Product cannot be wildcard when part is specified")
        
        return True, _("Valid CPE 2.3 format")
    
    @api.model
    def normalize_cpe_name(self, cpe_name):
        """Normalize CPE name for consistent storage and comparison"""
        if not cpe_name:
            return None
        
        # Basic normalization
        cpe_name = cpe_name.strip().lower()
        
        # Ensure CPE 2.3 prefix
        if not cpe_name.startswith('cpe:2.3:'):
            return None
        
        parts = cpe_name.split(':')
        if len(parts) < 12:
            return None
        
        # Normalize components
        normalized_parts = []
        for i, part in enumerate(parts):
            if i < 2:
                # Keep prefix as-is
                normalized_parts.append(part)
            else:
                # Normalize component
                normalized_parts.append(self._normalize_cpe_component(part))
        
        # Pad to 12 components if needed
        while len(normalized_parts) < 12:
            normalized_parts.append('*')
        
        return ':'.join(normalized_parts)
    
    def _normalize_cpe_component(self, component):
        """Normalize individual CPE component"""
        if not component or component == '*':
            return '*'
        
        # URL decode
        component = urllib.parse.unquote(component)
        
        # Handle CPE escaping
        component = component.replace('\\:', ':')
        component = component.replace('\\\\', '\\')
        
        # Remove extra whitespace
        component = component.strip()
        
        # URL encode back if needed
        if any(c in component for c in [':', ' ', '\\', '/']):
            component = urllib.parse.quote(component, safe='')
        
        return component
    
    @api.model
    def parse_cpe_name(self, cpe_name):
        """Parse CPE name into structured components"""
        if not cpe_name or not cpe_name.startswith('cpe:2.3:'):
            return {}
        
        parts = cpe_name.split(':')
        if len(parts) < 12:
            return {}
        
        component_names = [
            'cpe_version', 'format', 'part', 'vendor', 'product', 'version',
            'update', 'edition', 'language', 'sw_edition', 'target_sw', 'target_hw', 'other'
        ]
        
        parsed = {}
        for i, name in enumerate(component_names):
            if i < len(parts):
                value = self._decode_cpe_component(parts[i])
                if value and value != '*':
                    parsed[name] = value
        
        return parsed
    
    def _decode_cpe_component(self, component):
        """Decode CPE component handling wildcards and escaping"""
        if not component or component == '*':
            return None
        
        # URL decode
        decoded = urllib.parse.unquote(component)
        
        # Handle CPE escaping
        decoded = decoded.replace('\\:', ':')
        decoded = decoded.replace('\\\\', '\\')
        
        return decoded if decoded else None
    
    @api.model
    def build_cpe_name(self, part='*', vendor='*', product='*', version='*', 
                       update='*', edition='*', language='*', sw_edition='*',
                       target_sw='*', target_hw='*', other='*'):
        """Build CPE 2.3 name from components"""
        components = [
            'cpe', '2.3', part or '*', vendor or '*', product or '*',
            version or '*', update or '*', edition or '*', language or '*',
            sw_edition or '*', target_sw or '*', target_hw or '*', other or '*'
        ]
        
        # Encode components that need it
        encoded_components = []
        for i, comp in enumerate(components):
            if i < 2:  # Skip 'cpe' and '2.3'
                encoded_components.append(comp)
            else:
                encoded_components.append(self._encode_cpe_component(comp))
        
        cpe_name = ':'.join(encoded_components)
        
        # Validate the built CPE name
        is_valid, message = self.validate_cpe_name(cpe_name)
        if not is_valid:
            raise ValidationError(_("Built CPE name is invalid: %s") % message)
        
        return cpe_name
    
    def _encode_cpe_component(self, component):
        """Encode CPE component with proper escaping"""
        if not component or component == '*':
            return '*'
        
        # Escape special characters
        component = component.replace('\\', '\\\\')
        component = component.replace(':', '\\:')
        
        # URL encode if needed
        if any(c in component for c in [' ', '/', '?', '#', '[', ']', '@']):
            component = urllib.parse.quote(component, safe='\\:')
        
        return component


class CpeSuggestionService(models.AbstractModel):
    """Service for generating CPE suggestions based on asset information"""
    _name = 'vuln.fw.nvd.cpe.suggestion.service'
    _description = 'CPE Suggestion Service'

    @api.model
    def generate_suggestions(self, asset_info, limit=20):
        """Generate CPE suggestions based on asset information"""
        suggestions = []
        
        # Get base domain
        domain = [('deprecated', '=', False)]
        
        # Apply filters based on available information
        if asset_info.get('vendor'):
            vendor_suggestions = self._get_vendor_suggestions(asset_info, domain, limit)
            suggestions.extend(vendor_suggestions)
        
        if asset_info.get('product') and not suggestions:
            product_suggestions = self._get_product_suggestions(asset_info, domain, limit)
            suggestions.extend(product_suggestions)
        
        # If still no suggestions, do a broader search
        if not suggestions:
            broad_suggestions = self._get_broad_suggestions(asset_info, domain, limit)
            suggestions.extend(broad_suggestions)
        
        # Remove duplicates and sort by confidence
        seen = set()
        unique_suggestions = []
        for suggestion in suggestions:
            if suggestion['cpe_name'] not in seen:
                seen.add(suggestion['cpe_name'])
                unique_suggestions.append(suggestion)
        
        # Sort by confidence score
        unique_suggestions.sort(key=lambda x: x['confidence'], reverse=True)
        
        return unique_suggestions[:limit]
    
    def _get_vendor_suggestions(self, asset_info, base_domain, limit):
        """Get suggestions based on vendor matching"""
        vendor = asset_info['vendor']
        suggestions = []
        
        # Exact vendor match
        domain = base_domain + [('vendor', '=ilike', vendor)]
        cpe_entries = self.env['vuln.fw.nvd.cpe.dictionary'].search(domain, limit=limit * 2)
        
        for cpe in cpe_entries:
            confidence = self._calculate_confidence(asset_info, cpe)
            if confidence > 0.2:  # Minimum confidence threshold
                suggestions.append({
                    'cpe_name': cpe.cpe_name,
                    'title': cpe.title,
                    'vendor': cpe.vendor,
                    'product': cpe.product,
                    'version': cpe.version,
                    'confidence': confidence,
                    'match_reason': self._get_match_reason(asset_info, cpe),
                    'vulnerability_count': cpe.vulnerability_count,
                    'cpe_id': cpe.id
                })
        
        # Fuzzy vendor match if exact didn't yield enough results
        if len(suggestions) < limit // 2:
            domain = base_domain + [('vendor', 'ilike', f'%{vendor}%')]
            fuzzy_cpes = self.env['vuln.fw.nvd.cpe.dictionary'].search(domain, limit=limit)
            
            for cpe in fuzzy_cpes:
                if cpe.cpe_name not in [s['cpe_name'] for s in suggestions]:
                    confidence = self._calculate_confidence(asset_info, cpe)
                    if confidence > 0.1:
                        suggestions.append({
                            'cpe_name': cpe.cpe_name,
                            'title': cpe.title,
                            'vendor': cpe.vendor,
                            'product': cpe.product,
                            'version': cpe.version,
                            'confidence': confidence * 0.8,  # Reduce confidence for fuzzy match
                            'match_reason': f"Fuzzy vendor match: {self._get_match_reason(asset_info, cpe)}",
                            'vulnerability_count': cpe.vulnerability_count,
                            'cpe_id': cpe.id
                        })
        
        return suggestions
    
    def _get_product_suggestions(self, asset_info, base_domain, limit):
        """Get suggestions based on product matching"""
        product = asset_info['product']
        suggestions = []
        
        # Product-based search
        domain = base_domain + [('product', 'ilike', f'%{product}%')]
        cpe_entries = self.env['vuln.fw.nvd.cpe.dictionary'].search(domain, limit=limit)
        
        for cpe in cpe_entries:
            confidence = self._calculate_confidence(asset_info, cpe)
            if confidence > 0.1:
                suggestions.append({
                    'cpe_name': cpe.cpe_name,
                    'title': cpe.title,
                    'vendor': cpe.vendor,
                    'product': cpe.product,
                    'version': cpe.version,
                    'confidence': confidence,
                    'match_reason': self._get_match_reason(asset_info, cpe),
                    'vulnerability_count': cpe.vulnerability_count,
                    'cpe_id': cpe.id
                })
        
        return suggestions
    
    def _get_broad_suggestions(self, asset_info, base_domain, limit):
        """Get suggestions using broader search criteria"""
        suggestions = []
        
        # Search in title and search_text
        search_terms = []
        for field in ['vendor', 'product', 'version']:
            if asset_info.get(field):
                search_terms.append(asset_info[field])
        
        if not search_terms:
            return []
        
        # Build search query
        for term in search_terms:
            domain = base_domain + [
                '|', ('title', 'ilike', f'%{term}%'),
                ('search_text', 'ilike', f'%{term}%')
            ]
            
            cpe_entries = self.env['vuln.fw.nvd.cpe.dictionary'].search(domain, limit=limit//len(search_terms) + 5)
            
            for cpe in cpe_entries:
                if cpe.cpe_name not in [s['cpe_name'] for s in suggestions]:
                    confidence = self._calculate_confidence(asset_info, cpe) * 0.5  # Lower confidence for broad match
                    if confidence > 0.05:
                        suggestions.append({
                            'cpe_name': cpe.cpe_name,
                            'title': cpe.title,
                            'vendor': cpe.vendor,
                            'product': cpe.product,
                            'version': cpe.version,
                            'confidence': confidence,
                            'match_reason': f"Broad search match for '{term}'",
                            'vulnerability_count': cpe.vulnerability_count,
                            'cpe_id': cpe.id
                        })
        
        return suggestions
    
    def _calculate_confidence(self, asset_info, cpe):
        """Calculate confidence score for CPE match"""
        confidence = 0.0
        
        # Vendor matching (40% weight)
        if asset_info.get('vendor') and cpe.vendor:
            vendor_similarity = self._calculate_similarity(
                asset_info['vendor'].lower(), 
                cpe.vendor.lower()
            )
            confidence += vendor_similarity * 0.4
        
        # Product matching (40% weight)
        if asset_info.get('product') and cpe.product:
            product_similarity = self._calculate_similarity(
                asset_info['product'].lower(),
                cpe.product.lower()
            )
            confidence += product_similarity * 0.4
        
        # Version matching (20% weight)
        if asset_info.get('version') and cpe.version:
            version_similarity = self._calculate_similarity(
                asset_info['version'].lower(),
                cpe.version.lower()
            )
            confidence += version_similarity * 0.2
        
        # Boost confidence for entries with more vulnerabilities (indicates importance)
        if cpe.vulnerability_count > 0:
            vulnerability_boost = min(0.1, cpe.vulnerability_count * 0.001)
            confidence += vulnerability_boost
        
        return min(confidence, 1.0)  # Cap at 1.0
    
    def _calculate_similarity(self, str1, str2):
        """Calculate similarity between two strings"""
        if not str1 or not str2:
            return 0.0
        
        # Use SequenceMatcher for similarity calculation
        matcher = SequenceMatcher(None, str1, str2)
        similarity = matcher.ratio()
        
        # Bonus for exact substring matches
        if str1 in str2 or str2 in str1:
            similarity = max(similarity, 0.8)
        
        # Bonus for word-level matches
        words1 = set(str1.split())
        words2 = set(str2.split())
        if words1 & words2:  # Common words
            word_overlap = len(words1 & words2) / max(len(words1), len(words2))
            similarity = max(similarity, word_overlap * 0.7)
        
        return similarity
    
    def _get_match_reason(self, asset_info, cpe):
        """Generate human-readable match reason"""
        reasons = []
        
        if asset_info.get('vendor') and cpe.vendor:
            if asset_info['vendor'].lower() == cpe.vendor.lower():
                reasons.append(f"Exact vendor match: {cpe.vendor}")
            elif asset_info['vendor'].lower() in cpe.vendor.lower():
                reasons.append(f"Vendor contains: {asset_info['vendor']}")
            elif cpe.vendor.lower() in asset_info['vendor'].lower():
                reasons.append(f"Asset vendor contains: {cpe.vendor}")
        
        if asset_info.get('product') and cpe.product:
            if asset_info['product'].lower() == cpe.product.lower():
                reasons.append(f"Exact product match: {cpe.product}")
            elif asset_info['product'].lower() in cpe.product.lower():
                reasons.append(f"Product contains: {asset_info['product']}")
            elif cpe.product.lower() in asset_info['product'].lower():
                reasons.append(f"Asset product contains: {cpe.product}")
        
        if asset_info.get('version') and cpe.version:
            if asset_info['version'].lower() == cpe.version.lower():
                reasons.append(f"Exact version match: {cpe.version}")
        
        return '; '.join(reasons) if reasons else 'General similarity'


class CpeNormalizationService(models.AbstractModel):
    """Service for normalizing asset information for CPE matching"""
    _name = 'vuln.fw.nvd.cpe.normalization.service'
    _description = 'CPE Normalization Service'

    @api.model
    def normalize_asset_info(self, raw_info):
        """Normalize raw asset information for CPE matching"""
        normalized = {}
        
        # Normalize vendor
        if raw_info.get('vendor'):
            normalized['vendor'] = self._normalize_vendor(raw_info['vendor'])
        
        # Normalize product
        if raw_info.get('product'):
            normalized['product'] = self._normalize_product(raw_info['product'])
        
        # Normalize version
        if raw_info.get('version'):
            normalized['version'] = self._normalize_version(raw_info['version'])
        
        return normalized
    
    def _normalize_vendor(self, vendor):
        """Normalize vendor name"""
        if not vendor:
            return None
        
        vendor = vendor.strip().lower()
        
        # Common vendor normalizations
        vendor_mappings = {
            'microsoft corporation': 'microsoft',
            'microsoft corp': 'microsoft',
            'apple inc': 'apple',
            'apple computer': 'apple',
            'google inc': 'google',
            'google llc': 'google',
            'oracle corporation': 'oracle',
            'oracle corp': 'oracle',
            'adobe systems': 'adobe',
            'adobe inc': 'adobe',
            'vmware inc': 'vmware',
            'citrix systems': 'citrix',
        }
        
        # Apply mappings
        for original, normalized in vendor_mappings.items():
            if vendor == original:
                vendor = normalized
                break
        
        # Remove common suffixes
        suffixes_to_remove = [
            ' inc', ' inc.', ' corp', ' corp.', ' corporation', ' ltd', ' ltd.',
            ' llc', ' llc.', ' limited', ' gmbh', ' ag', ' sa', ' bv', ' oy'
        ]
        
        for suffix in suffixes_to_remove:
            if vendor.endswith(suffix):
                vendor = vendor[:-len(suffix)].strip()
        
        return vendor
    
    def _normalize_product(self, product):
        """Normalize product name"""
        if not product:
            return None
        
        product = product.strip()
        
        # Remove version information that might be embedded in product name
        # Common patterns: "Product v1.2", "Product 2019", "Product (64-bit)"
        patterns_to_remove = [
            r'\s+v?\d+\.\d+.*$',  # Version numbers
            r'\s+\d{4}.*$',       # Year versions
            r'\s+\(.*\)$',        # Parenthetical info
            r'\s+\[.*\]$',        # Bracketed info
        ]
        
        for pattern in patterns_to_remove:
            product = re.sub(pattern, '', product, flags=re.IGNORECASE)
        
        # Normalize case (keep original case but prepare for comparison)
        return product.strip()
    
    def _normalize_version(self, version):
        """Normalize version string"""
        if not version:
            return None
        
        version = version.strip()
        
        # Remove common prefixes
        prefixes_to_remove = ['v', 'version', 'ver', 'build', 'release', 'r']
        for prefix in prefixes_to_remove:
            if version.lower().startswith(prefix.lower()):
                version = version[len(prefix):].strip()
                break
        
        # Normalize separators (keep dots, convert others to dots)
        version = re.sub(r'[-_\s]+', '.', version)
        
        # Remove trailing zeros in version components
        parts = version.split('.')
        normalized_parts = []
        for part in parts:
            # Keep non-numeric parts as-is, normalize numeric parts
            if part.isdigit():
                normalized_parts.append(str(int(part)))
            else:
                normalized_parts.append(part)
        
        return '.'.join(normalized_parts)
    
    @api.model
    def extract_asset_info(self, asset_record):
        """Extract relevant information from asset record for CPE matching"""
        info = {}
        
        # Define field mappings for different asset types
        field_mappings = {
            'vendor': [
                'vendor', 'manufacturer', 'brand', 'company', 'publisher',
                'developer', 'vendor_name', 'manufacturer_name'
            ],
            'product': [
                'product', 'model', 'software_name', 'application_name', 'name',
                'product_name', 'software', 'application', 'service_name'
            ],
            'version': [
                'version', 'software_version', 'firmware_version', 'app_version',
                'product_version', 'release_version', 'build_version'
            ]
        }
        
        # Extract information based on available fields
        for info_type, field_names in field_mappings.items():
            for field_name in field_names:
                if hasattr(asset_record, field_name):
                    value = getattr(asset_record, field_name)
                    if value:
                        info[info_type] = str(value)
                        break
        
        # Special handling for Lansweeper assets
        if hasattr(asset_record, '_name') and 'lansweeper' in asset_record._name:
            info.update(self._extract_lansweeper_info(asset_record))
        
        # Normalize extracted information
        return self.normalize_asset_info(info)
    
    def _extract_lansweeper_info(self, lansweeper_asset):
        """Extract CPE-relevant info from Lansweeper asset"""
        info = {}
        
        # Try to get OS information
        if hasattr(lansweeper_asset, 'operating_system'):
            os_info = lansweeper_asset.operating_system
            if os_info:
                info['vendor'] = 'microsoft' if 'windows' in os_info.lower() else None
                info['product'] = os_info
        
        # Try to get hardware information
        if hasattr(lansweeper_asset, 'computer_manufacturer'):
            info['vendor'] = lansweeper_asset.computer_manufacturer
        
        if hasattr(lansweeper_asset, 'computer_model'):
            info['product'] = lansweeper_asset.computer_model
        
        return info
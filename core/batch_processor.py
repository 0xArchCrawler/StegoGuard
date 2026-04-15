"""
StegoGuard Batch Processor
Process multiple images in parallel
"""

import asyncio
from typing import Dict, List, Optional, Callable
from datetime import datetime
from pathlib import Path
import concurrent.futures
import uuid


class BatchProcessor:
    """
    Batch processing engine for analyzing multiple images
    """

    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self.batches = {}
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)

    def create_batch(self, batch_id: str, file_paths: List[str], options: Dict) -> Dict:
        """Create a new batch job"""
        batch = {
            'id': batch_id,
            'file_paths': file_paths,
            'total': len(file_paths),
            'completed': 0,
            'failed': 0,
            'status': 'queued',
            'options': options,
            'results': [],
            'created_at': datetime.now().isoformat()
        }

        self.batches[batch_id] = batch
        return batch

    def get_batch(self, batch_id: str) -> Optional[Dict]:
        """Get batch by ID"""
        return self.batches.get(batch_id)

    def process_batch(
        self,
        batch_id: str,
        progress_callback: Optional[Callable] = None
    ):
        """Process batch of images"""
        batch = self.batches.get(batch_id)
        if not batch:
            return

        batch['status'] = 'running'
        batch['started_at'] = datetime.now().isoformat()

        from .analyzer import AdvancedAnalyzer
        analyzer = AdvancedAnalyzer()

        # Process files
        for i, file_path in enumerate(batch['file_paths']):
            try:
                # Run analysis
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

                result = loop.run_until_complete(
                    analyzer.analyze_image(file_path, batch['options'])
                )

                loop.close()

                batch['results'].append(result)
                batch['completed'] += 1

            except Exception as e:
                batch['results'].append({
                    'file_path': file_path,
                    'error': str(e),
                    'status': 'failed'
                })
                batch['failed'] += 1

            # Update progress
            progress = (i + 1) / batch['total'] * 100
            batch['progress'] = progress

            if progress_callback:
                progress_callback(progress)

        batch['status'] = 'completed'
        batch['completed_at'] = datetime.now().isoformat()

    def get_batch_summary(self, batch_id: str) -> Dict:
        """Get summary of batch processing"""
        batch = self.batches.get(batch_id)
        if not batch:
            return {}

        summary = {
            'batch_id': batch_id,
            'total': batch['total'],
            'completed': batch['completed'],
            'failed': batch['failed'],
            'status': batch['status'],
            'threat_summary': {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0,
                'MINIMAL': 0
            }
        }

        # Aggregate threat levels
        for result in batch.get('results', []):
            if result.get('status') == 'failed':
                continue

            threat_level = result.get('threat_analysis', {}).get('threat_assessment', {}).get('level', 'UNKNOWN')
            if threat_level in summary['threat_summary']:
                summary['threat_summary'][threat_level] += 1

        return summary

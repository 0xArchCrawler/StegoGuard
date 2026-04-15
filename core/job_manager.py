"""
StegoGuard Job Manager
Manages analysis jobs, queue, and state
"""

from typing import Dict, List, Optional
from datetime import datetime, timedelta
from pathlib import Path
import json
import threading


class JobManager:
    """
    Manages analysis jobs with persistence and state tracking
    """

    def __init__(self, storage_path: Optional[Path] = None):
        self.jobs = {}
        self.lock = threading.Lock()

        if storage_path is None:
            storage_path = Path.home() / '.stegoguard' / 'jobs'

        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)

        # Load existing jobs
        self._load_jobs()

    def add_job(self, job: Dict) -> str:
        """Add new job to queue"""
        with self.lock:
            job_id = job['id']
            job['created_at'] = datetime.now().isoformat()
            job['updated_at'] = datetime.now().isoformat()
            job['status'] = job.get('status', 'queued')

            self.jobs[job_id] = job
            self._save_job(job_id)

            return job_id

    def get_job(self, job_id: str) -> Optional[Dict]:
        """Get job by ID"""
        with self.lock:
            return self.jobs.get(job_id)

    def update_job_status(self, job_id: str, status: str):
        """Update job status"""
        with self.lock:
            if job_id in self.jobs:
                self.jobs[job_id]['status'] = status
                self.jobs[job_id]['updated_at'] = datetime.now().isoformat()
                self._save_job(job_id)

    def update_job(self, job_id: str, updates: Dict):
        """Update job with arbitrary data"""
        with self.lock:
            if job_id in self.jobs:
                self.jobs[job_id].update(updates)
                self.jobs[job_id]['updated_at'] = datetime.now().isoformat()
                self._save_job(job_id)

    def list_jobs(self, status: Optional[str] = None, limit: int = 50) -> List[Dict]:
        """List jobs with optional filtering"""
        with self.lock:
            jobs = list(self.jobs.values())

            if status:
                jobs = [j for j in jobs if j.get('status') == status]

            # Sort by created_at desc
            jobs.sort(key=lambda x: x.get('created_at', ''), reverse=True)

            return jobs[:limit]

    def cancel_job(self, job_id: str) -> bool:
        """Cancel a running job"""
        with self.lock:
            if job_id in self.jobs:
                job = self.jobs[job_id]
                if job['status'] in ['queued', 'running']:
                    job['status'] = 'cancelled'
                    job['cancelled_at'] = datetime.now().isoformat()
                    self._save_job(job_id)
                    return True
        return False

    def delete_job(self, job_id: str) -> bool:
        """Delete a job"""
        with self.lock:
            if job_id in self.jobs:
                del self.jobs[job_id]
                job_file = self.storage_path / f"{job_id}.json"
                if job_file.exists():
                    job_file.unlink()
                return True
        return False

    def get_total_analyses(self) -> int:
        """Get total number of analyses"""
        with self.lock:
            return len(self.jobs)

    def get_recent_analyses(self, limit: int = 10) -> List[Dict]:
        """Get recent analyses"""
        return self.list_jobs(limit=limit)

    def get_threat_distribution(self) -> Dict:
        """Get distribution of threat levels"""
        with self.lock:
            distribution = {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0,
                'MINIMAL': 0,
                'UNKNOWN': 0
            }

            for job in self.jobs.values():
                if job.get('status') == 'completed':
                    results = job.get('results', {})
                    threat_analysis = results.get('threat_analysis', {})
                    level = threat_analysis.get('threat_assessment', {}).get('level', 'UNKNOWN')

                    if level in distribution:
                        distribution[level] += 1
                    else:
                        distribution['UNKNOWN'] += 1

            return distribution

    def get_detection_stats(self) -> Dict:
        """Get detection statistics"""
        with self.lock:
            stats = {
                'total_detections': 0,
                'avg_anomalies': 0,
                'avg_confidence': 0,
                'module_stats': {}
            }

            completed_jobs = [
                j for j in self.jobs.values()
                if j.get('status') == 'completed'
            ]

            if not completed_jobs:
                return stats

            total_anomalies = 0
            total_confidence = 0

            for job in completed_jobs:
                results = job.get('results', {})
                detection = results.get('detection', {})

                anomalies = detection.get('anomaly_count', 0)
                total_anomalies += anomalies

                confidence = detection.get('confidence', 0)
                total_confidence += confidence

                if anomalies > 0:
                    stats['total_detections'] += 1

            stats['avg_anomalies'] = total_anomalies / len(completed_jobs)
            stats['avg_confidence'] = total_confidence / len(completed_jobs)

            return stats

    def get_timeline(self, days: int = 7) -> Dict:
        """Get analysis timeline"""
        with self.lock:
            timeline = {}
            cutoff_date = datetime.now() - timedelta(days=days)

            for job in self.jobs.values():
                created_at = job.get('created_at')
                if not created_at:
                    continue

                created_date = datetime.fromisoformat(created_at)
                if created_date < cutoff_date:
                    continue

                date_key = created_date.strftime('%Y-%m-%d')

                if date_key not in timeline:
                    timeline[date_key] = {
                        'total': 0,
                        'threats_found': 0,
                        'clean': 0
                    }

                timeline[date_key]['total'] += 1

                if job.get('status') == 'completed':
                    results = job.get('results', {})
                    detection = results.get('detection', {})

                    if detection.get('anomaly_count', 0) > 0:
                        timeline[date_key]['threats_found'] += 1
                    else:
                        timeline[date_key]['clean'] += 1

            return timeline

    def get_active_threats(self) -> List[Dict]:
        """Get currently active threats"""
        with self.lock:
            active_threats = []

            for job in self.jobs.values():
                if job.get('status') != 'completed':
                    continue

                results = job.get('results', {})
                threat_analysis = results.get('threat_analysis', {})
                threat_level = threat_analysis.get('threat_assessment', {}).get('level', 'UNKNOWN')

                if threat_level in ['HIGH', 'CRITICAL']:
                    active_threats.append({
                        'job_id': job['id'],
                        'file_path': job.get('file_path', 'unknown'),
                        'threat_level': threat_level,
                        'detected_at': job.get('completed_at', job.get('created_at')),
                        'apt_actor': threat_analysis.get('apt_attribution', {}).get('likely_actor'),
                        'risk_score': threat_analysis.get('risk_score', 0)
                    })

            # Sort by risk score
            active_threats.sort(key=lambda x: x['risk_score'], reverse=True)

            return active_threats

    def get_active_count(self) -> int:
        """Get count of active jobs"""
        with self.lock:
            return len([j for j in self.jobs.values() if j.get('status') == 'running'])

    def get_queued_count(self) -> int:
        """Get count of queued jobs"""
        with self.lock:
            return len([j for j in self.jobs.values() if j.get('status') == 'queued'])

    def _save_job(self, job_id: str):
        """Save job to disk"""
        try:
            job = self.jobs[job_id]
            job_file = self.storage_path / f"{job_id}.json"

            with open(job_file, 'w') as f:
                json.dump(job, f, indent=2)
        except Exception as e:
            print(f"Error saving job {job_id}: {e}")

    def _load_jobs(self):
        """Load jobs from disk"""
        try:
            for job_file in self.storage_path.glob("*.json"):
                with open(job_file, 'r') as f:
                    job = json.load(f)
                    self.jobs[job['id']] = job
        except Exception as e:
            print(f"Error loading jobs: {e}")

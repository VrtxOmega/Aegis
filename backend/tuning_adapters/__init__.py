"""
Tuning Adapter Interface — Base class for all hardware tuning providers.
Each adapter wraps a specific tool (ThrottleStop, MSI Afterburner, MSI Center)
and exposes a uniform interface for detect/apply/verify/revert.
"""
from abc import ABC, abstractmethod
from datetime import datetime


class TuningAdapter(ABC):
    """Base interface for hardware tuning adapters."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable provider name."""
        ...

    @property
    @abstractmethod
    def subsystem(self) -> str:
        """What this adapter controls: 'cpu', 'gpu', or 'fan'."""
        ...

    @abstractmethod
    def available(self) -> dict:
        """Check if the underlying tool is installed and accessible.
        Returns: {'installed': bool, 'running': bool, 'path': str|None, 'version': str|None}
        """
        ...

    @abstractmethod
    def detect_state(self) -> dict:
        """Read current hardware state from this provider.
        Returns provider-specific dict with at minimum:
          {'status': 'ACTIVE'|'INACTIVE'|'NOT_INSTALLED'|'UNKNOWN', ...values...}
        """
        ...

    @abstractmethod
    def apply(self, desired: dict) -> dict:
        """Apply desired settings.
        Returns: {'success': bool, 'applied': dict, 'message': str}
        """
        ...

    @abstractmethod
    def verify(self, desired: dict) -> dict:
        """Verify that the desired settings are actually in effect.
        Returns: {'verified': bool, 'expected': dict, 'actual': dict, 'mismatches': list}
        """
        ...

    @abstractmethod
    def revert(self, baseline: dict) -> dict:
        """Revert to a saved baseline state.
        Returns: {'success': bool, 'reverted_to': dict, 'message': str}
        """
        ...

    def _timestamp(self) -> str:
        return datetime.now().isoformat()

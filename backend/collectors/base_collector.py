"""
Base Collector Module for MiniSIEM X
Guarantees read-only, safe, non-destructive event log ingestion.
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

class BaseCollector(ABC):
    def __init__(self, name: str, source_type: str):
        self.name = name
        self.source_type = source_type
        self.is_connected = True
        self.error_count = 0

    @abstractmethod
    def collect(self, raw_input: Any) -> List[Dict[str, Any]]:
        """
        Parses incoming raw input into an intermediate list of event dictionaries.
        Must never perform destructive actions on the host or target system.
        """
        pass

    def mark_error(self):
        self.error_count += 1


#!/usr/bin/env python3
"""
Payload Loader Utility

Load test payloads from external files to avoid inline classifier blocks.
Supports metadata extraction and filtering.
"""

import os
import json
from pathlib import Path
from typing import Dict, Tuple, Optional, List
from dataclasses import dataclass


@dataclass
class Payload:
    """Represents a loaded payload"""
    content: str
    filename: str
    filepath: str
    metadata: Dict = None

    def __str__(self):
        return self.content

    def preview(self, chars: int = 100) -> str:
        """Get preview of payload"""
        return self.content[:chars] + ("..." if len(self.content) > chars else "")


class PayloadLoader:
    """Loads payloads from external files"""

    def __init__(self, base_dir: str = "payloads"):
        self.base_dir = base_dir
        self.cache = {}

    def load(self, filename: str, directory: Optional[str] = None) -> Optional[Payload]:
        """
        Load a single payload file.

        Args:
            filename: Name of payload file (e.g., "api_key_indirect.txt")
            directory: Subdirectory within base_dir (e.g., "llm02"). If None, searches all dirs.

        Returns:
            Payload object or None if not found
        """
        if directory:
            filepath = os.path.join(self.base_dir, directory, filename)
        else:
            # Search all subdirectories
            filepath = self._find_file(filename)
            if not filepath:
                return None

        if not os.path.exists(filepath):
            return None

        # Check cache
        if filepath in self.cache:
            return self.cache[filepath]

        # Load file
        try:
            with open(filepath, 'r') as f:
                content = f.read().strip()

            # Extract metadata if present
            metadata = self._extract_metadata(content)
            if metadata:
                # Remove metadata from content
                content = content.split("---", 2)[2].strip()

            payload = Payload(
                content=content,
                filename=filename,
                filepath=filepath,
                metadata=metadata
            )
            self.cache[filepath] = payload
            return payload

        except Exception as e:
            print(f"ERROR loading {filepath}: {e}")
            return None

    def load_all(self, directory: str) -> List[Payload]:
        """Load all payloads from a directory"""
        payloads = []
        dirpath = os.path.join(self.base_dir, directory)

        if not os.path.exists(dirpath):
            print(f"WARNING: Directory not found: {dirpath}")
            return payloads

        for filename in sorted(os.listdir(dirpath)):
            if filename.endswith(".txt"):
                payload = self.load(filename, directory)
                if payload:
                    payloads.append(payload)

        return payloads

    def load_matching(self, pattern: str) -> List[Payload]:
        """Load all payloads matching a pattern (e.g., "*api*")"""
        payloads = []

        for dirpath, dirnames, filenames in os.walk(self.base_dir):
            for filename in filenames:
                if filename.endswith(".txt") and pattern.lower() in filename.lower():
                    rel_dir = os.path.relpath(dirpath, self.base_dir)
                    payload = self.load(filename, rel_dir if rel_dir != "." else None)
                    if payload:
                        payloads.append(payload)

        return payloads

    def list_all(self) -> Dict[str, List[str]]:
        """List all available payloads by directory"""
        result = {}

        if not os.path.exists(self.base_dir):
            return result

        for dirpath, dirnames, filenames in os.walk(self.base_dir):
            rel_dir = os.path.relpath(dirpath, self.base_dir)
            txt_files = [f for f in filenames if f.endswith(".txt")]

            if txt_files:
                if rel_dir == ".":
                    rel_dir = "root"
                result[rel_dir] = txt_files

        return result

    def _find_file(self, filename: str) -> Optional[str]:
        """Search for filename in all subdirectories"""
        for dirpath, dirnames, filenames in os.walk(self.base_dir):
            if filename in filenames:
                return os.path.join(dirpath, filename)
        return None

    @staticmethod
    def _extract_metadata(content: str) -> Optional[Dict]:
        """Extract YAML metadata from payload if present"""
        if not content.startswith("---"):
            return None

        try:
            parts = content.split("---", 2)
            if len(parts) < 3:
                return None

            # Try to parse as YAML
            try:
                import yaml
                metadata = yaml.safe_load(parts[1])
                return metadata if isinstance(metadata, dict) else None
            except ImportError:
                # Fallback to simple key:value parsing
                metadata = {}
                for line in parts[1].strip().split("\n"):
                    if ":" in line:
                        key, value = line.split(":", 1)
                        metadata[key.strip()] = value.strip()
                return metadata if metadata else None

        except Exception:
            return None

    def filter_by_metadata(self, key: str, value: str) -> List[Payload]:
        """Filter loaded payloads by metadata"""
        result = []

        for dirpath, dirnames, filenames in os.walk(self.base_dir):
            for filename in filenames:
                if filename.endswith(".txt"):
                    rel_dir = os.path.relpath(dirpath, self.base_dir)
                    payload = self.load(filename, rel_dir if rel_dir != "." else None)

                    if payload and payload.metadata:
                        if payload.metadata.get(key) == value:
                            result.append(payload)

        return result

    def clear_cache(self):
        """Clear the in-memory cache"""
        self.cache.clear()


# Global instance for convenience
_loader = PayloadLoader()


def load_payload(filename: str, directory: Optional[str] = None) -> Optional[str]:
    """Load a payload and return as string"""
    payload = _loader.load(filename, directory)
    return str(payload) if payload else None


def load_payloads(directory: str) -> List[str]:
    """Load all payloads from a directory and return as strings"""
    return [str(p) for p in _loader.load_all(directory)]


def list_payloads() -> Dict[str, List[str]]:
    """List all available payloads"""
    return _loader.list_all()


def get_loader() -> PayloadLoader:
    """Get the global payload loader instance"""
    return _loader


# CLI for testing
if __name__ == "__main__":
    import sys

    loader = get_loader()

    if len(sys.argv) > 1:
        if sys.argv[1] == "list":
            # List all payloads
            payloads = loader.list_all()
            if not payloads:
                print("No payloads found.")
            else:
                print("Available payloads:\n")
                for directory, files in sorted(payloads.items()):
                    print(f"  {directory}/")
                    for f in sorted(files):
                        print(f"    - {f}")

        elif sys.argv[1] == "load" and len(sys.argv) > 2:
            # Load specific payload
            directory = sys.argv[2] if len(sys.argv) > 3 else None
            filename = sys.argv[3] if len(sys.argv) > 3 else sys.argv[2]

            payload = loader.load(filename, directory)
            if payload:
                print(f"Loaded: {payload.filepath}\n")
                if payload.metadata:
                    print("Metadata:")
                    for k, v in payload.metadata.items():
                        print(f"  {k}: {v}")
                    print()
                print("Content:")
                print(payload.content)
            else:
                print(f"ERROR: Payload not found")

        elif sys.argv[1] == "find" and len(sys.argv) > 2:
            # Find payloads matching pattern
            pattern = sys.argv[2]
            payloads = loader.load_matching(pattern)
            if payloads:
                print(f"Found {len(payloads)} payload(s) matching '{pattern}':\n")
                for p in payloads:
                    print(f"  {p.filepath}")
                    print(f"    {p.preview(80)}\n")
            else:
                print(f"No payloads found matching '{pattern}'")

        else:
            print("Usage:")
            print("  python payload_loader.py list              # List all payloads")
            print("  python payload_loader.py load <file>       # Load payload by filename")
            print("  python payload_loader.py load <dir> <file> # Load from specific directory")
            print("  python payload_loader.py find <pattern>    # Find payloads by pattern")
    else:
        # Show summary
        payloads = loader.list_all()
        print(f"Payload Loader ({loader.base_dir}/)")
        print(f"Total directories: {len(payloads)}")
        total_files = sum(len(files) for files in payloads.values())
        print(f"Total payloads: {total_files}")
        print("\nRun with 'list' to see all payloads")

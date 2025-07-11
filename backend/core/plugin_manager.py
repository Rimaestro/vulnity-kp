import asyncio
import importlib
import inspect
import logging
import os
import pkgutil
import sys
from datetime import datetime
from typing import Dict, List, Type, Any, Set, Optional

from core.base_scanner import BaseScanner
from core.models import ScanOptions, ScanResult, ScanStatus, Vulnerability


class PluginManager:
    """
    Manager for loading and running scanner plugins.
    
    This class is responsible for discovering, loading, and executing scanner plugins.
    It maintains a registry of available plugins and provides methods to run them.
    """
    
    def __init__(self):
        self.plugins: Dict[str, Type[BaseScanner]] = {}
        self.active_scanners: Dict[str, BaseScanner] = {}
        self.logger = logging.getLogger("plugin_manager")
    
    def discover_plugins(self, plugins_package: str = "plugins") -> None:
        """
        Discover available plugins in the specified package.
        
        Args:
            plugins_package: The package containing plugins to discover
        """
        self.logger.info(f"Discovering plugins in package: {plugins_package}")
        
        # Ensure the package is in the Python path
        package_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if package_path not in sys.path:
            sys.path.insert(0, package_path)
        
        # Import the plugins package
        try:
            package = importlib.import_module(plugins_package)
        except ImportError:
            self.logger.error(f"Failed to import plugins package: {plugins_package}")
            return
        
        # Walk through all modules in the package and its subpackages
        for _, name, is_pkg in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
            if is_pkg:
                # Skip packages, we only want modules
                continue
            
            try:
                # Import the module
                module = importlib.import_module(name)
                
                # Find all BaseScanner subclasses in the module
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    
                    # Check if it's a class, a subclass of BaseScanner, and not BaseScanner itself
                    if (inspect.isclass(attr) and 
                        issubclass(attr, BaseScanner) and 
                        attr is not BaseScanner):
                        
                        # Register the plugin
                        plugin_name = attr.__name__
                        self.plugins[plugin_name] = attr
                        self.logger.info(f"Discovered plugin: {plugin_name}")
            
            except Exception as e:
                self.logger.error(f"Error loading module {name}: {str(e)}")
    
    def get_available_plugins(self) -> Dict[str, Type[BaseScanner]]:
        """Return the dictionary of available plugins."""
        return self.plugins
    
    def get_plugin_names(self) -> List[str]:
        """Return the list of available plugin names."""
        return list(self.plugins.keys())
    
    def get_plugin(self, name: str) -> Optional[Type[BaseScanner]]:
        """
        Get a plugin by name.
        
        Args:
            name: The name of the plugin to get
            
        Returns:
            The plugin class, or None if not found
        """
        return self.plugins.get(name)
    
    async def create_scanner(self, plugin_name: str, options: ScanOptions) -> BaseScanner:
        """
        Create and initialize a scanner instance.
        
        Args:
            plugin_name: The name of the plugin to create
            options: Scanner options
            
        Returns:
            Initialized scanner instance
            
        Raises:
            ValueError: If the plugin is not found
        """
        plugin_class = self.get_plugin(plugin_name)
        if not plugin_class:
            raise ValueError(f"Plugin not found: {plugin_name}")
        
        scanner = plugin_class()
        await scanner.setup(options)
        
        self.active_scanners[plugin_name] = scanner
        return scanner
    
    async def run_scan(self, target_url: str, scan_types: List[str], options: ScanOptions) -> ScanResult:
        """
        Run a scan using the specified plugins.
        
        Args:
            target_url: The URL to scan
            scan_types: List of plugin names to run
            options: Scanner options
            
        Returns:
            Scan result containing vulnerabilities and statistics
        """
        self.logger.info(f"Starting scan on {target_url} with plugins: {scan_types}")
        
        # Prepare scan result
        scan_id = options.custom_parameters.get("scan_id", str(__import__("uuid").uuid4()))
        scan_result = ScanResult(
            scan_id=scan_id,
            target_url=target_url,
            start_time=datetime.now(),
            status=ScanStatus.RUNNING,
            options=options
        )
        
        # Keep track of created scanners for cleanup
        scanners_to_cleanup = []
        
        try:
            # Initialize and run each scanner
            tasks = []
            for plugin_name in scan_types:
                if plugin_name not in self.plugins:
                    self.logger.warning(f"Plugin not found: {plugin_name}")
                    continue
                
                scanner = await self.create_scanner(plugin_name, options)
                scanners_to_cleanup.append(scanner)
                
                # Create task for this scanner
                task = asyncio.create_task(scanner.scan(target_url))
                tasks.append((plugin_name, task))
                
                # Update statistics
                scan_result.statistics.plugins_executed[plugin_name] = 0
            
            # Process results as they complete
            all_vulnerabilities: List[Vulnerability] = []
            for plugin_name, task in tasks:
                try:
                    vulnerabilities = await task
                    all_vulnerabilities.extend(vulnerabilities)
                    
                    # Update statistics
                    scan_result.statistics.plugins_executed[plugin_name] = len(vulnerabilities)
                    scan_result.statistics.vulnerabilities_found += len(vulnerabilities)
                    
                    self.logger.info(f"Plugin {plugin_name} found {len(vulnerabilities)} vulnerabilities")
                
                except Exception as e:
                    self.logger.error(f"Error running plugin {plugin_name}: {str(e)}")
            
            # Update scan result
            scan_result.vulnerabilities = all_vulnerabilities
            scan_result.end_time = datetime.now()
            scan_result.status = ScanStatus.COMPLETED
            scan_result.statistics.elapsed_time = (scan_result.end_time - scan_result.start_time).total_seconds()
            
        except Exception as e:
            self.logger.error(f"Error during scan: {str(e)}")
            scan_result.status = ScanStatus.FAILED
            scan_result.end_time = datetime.now()
            
        finally:
            # Clean up resources
            for scanner in scanners_to_cleanup:
                try:
                    await scanner.cleanup()
                except Exception as e:
                    self.logger.error(f"Error cleaning up scanner: {str(e)}")
            
            return scan_result
    
    async def cleanup_all(self) -> None:
        """Clean up all active scanners."""
        for name, scanner in list(self.active_scanners.items()):
            try:
                await scanner.cleanup()
                del self.active_scanners[name]
            except Exception as e:
                self.logger.error(f"Error cleaning up scanner {name}: {str(e)}")


# Create a singleton instance
plugin_manager = PluginManager() 
# core/logger.py
import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional

class CarelLogger:
    def __init__(self, config_manager):
        self.config = config_manager
        self.log_dir = self.config.home_dir / "logs"
        self.setup_logging()
    
    def setup_logging(self):
        """Setup comprehensive logging system"""
        
        # Create log filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = self.log_dir / f"carel_{timestamp}.log"
        
        # Configure logging
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            handlers=[
                logging.FileHandler(log_file, encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        self.logger = logging.getLogger("CAREL")
        
        # Log startup information
        self.logger.info("🚀 CAREL v2.0 Started")
        self.logger.info(f"📁 Log file: {log_file}")
    
    def debug(self, message: str):
        self.logger.debug(f"🐛 {message}")
    
    def info(self, message: str):
        self.logger.info(f"ℹ️  {message}")
    
    def warning(self, message: str):
        self.logger.warning(f"⚠️  {message}")
    
    def error(self, message: str):
        self.logger.error(f"❌ {message}")
    
    def critical(self, message: str):
        self.logger.critical(f"💥 {message}")
    
    def scan_start(self, scan_type: str, target: str):
        self.logger.info(f"🎯 Starting {scan_type} scan for: {target}")
    
    def scan_complete(self, scan_type: str, target: str, results_count: int = 0):
        self.logger.info(f"✅ {scan_type} scan completed for {target}. Found: {results_count} items")

# Example usage
if __name__ == "__main__":
    config = ConfigManager()
    logger = CarelLogger(config)
    
    logger.info("This is an info message")
    logger.debug("Debug details")
    logger.warning("This is a warning")
    logger.error("This is an error")

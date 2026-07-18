"""
CyberTool Logger Module
"""
import logging
from datetime import datetime
from config import LOGS_DIR


class CyberLogger:
    """Centralized logging for CyberTool"""

    def __init__(self):
        self.log_file = LOGS_DIR / f"cybertool_{datetime.now().strftime('%Y%m%d')}.log"
        self._setup_logger()

    def _setup_logger(self):
        self.logger = logging.getLogger("CyberTool")
        self.logger.setLevel(logging.DEBUG)

        # File handler
        fh = logging.FileHandler(self.log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        self.logger.addHandler(fh)

    def info(self, module, message):
        self.logger.info(f"[{module}] {message}")

    def warning(self, module, message):
        self.logger.warning(f"[{module}] {message}")

    def error(self, module, message):
        self.logger.error(f"[{module}] {message}")

    def debug(self, module, message):
        self.logger.debug(f"[{module}] {message}")


logger = CyberLogger()
import logging

def setup_logger(name='webvulnscanner', level=logging.INFO):
    logger = logging.getLogger(name)  # name is a string, required
    if not logger.handlers:  # avoid duplicate handlers if already added
        handler = logging.StreamHandler()
        formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", "%H:%M:%S")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(level)
    return logger


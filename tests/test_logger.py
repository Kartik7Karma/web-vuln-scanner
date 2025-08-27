import logging
from core.logger import setup_logger


def test_setup_logger_returns_logger():
    logger = setup_logger("test_logger", level=logging.DEBUG)
    
    assert isinstance(logger, logging.Logger)
    assert logger.name == "test_logger"
    assert logger.level == logging.DEBUG


def test_logger_has_single_handler():
    logger = setup_logger("unique_logger")
    handlers = logger.handlers

    # Should only add one handler even if called multiple times
    logger_again = setup_logger("unique_logger")
    assert len(handlers) == 1
    assert handlers == logger_again.handlers


def test_logger_formatter_format():
    logger = setup_logger("format_test_logger")
    handler = logger.handlers[0]
    formatter = handler.formatter

    assert isinstance(formatter, logging.Formatter)
    expected_format = "[%(asctime)s] [%(levelname)s] %(message)s"
    expected_datefmt = "%H:%M:%S"

    assert formatter._fmt == expected_format
    assert formatter.datefmt == expected_datefmt

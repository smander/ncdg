"""Real firmware evaluation targets for CDG benchmark."""
from firmware.config import (
    UBOOT_VERSIONS, TFA_VERSIONS, FirmwareTarget, CVEEntry,
)
from firmware.builder import FirmwareBuilder
from firmware.extractor import FirmwareExtractor

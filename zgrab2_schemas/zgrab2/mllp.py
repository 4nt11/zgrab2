# zschema sub-schema for zgrab2's mllp module
# Registers zgrab2-mllp globally, and mllp with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas
from . import zgrab2

mllp_scan_response = SubRecord(
    {
        "result": SubRecord(
            {
                "detected": Boolean(),
                "ack_code": String(),
                "ack_text": String(),
                "sending_application": String(),
                "sending_facility": String(),
                "receiving_application": String(),
                "receiving_facility": String(),
                "message_type": String(),
                "processing_id": String(),
                "version": String(),
                "control_id": String(),
                "err_text": String(),
                "tls": zgrab2.tls_log,
                "raw": String(),
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-mllp", mllp_scan_response)

zgrab2.register_scan_response_type("mllp", mllp_scan_response)

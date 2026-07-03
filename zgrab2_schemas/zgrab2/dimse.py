# zschema sub-schema for zgrab2's dimse module
# Registers zgrab2-dimse globally, and dimse with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas
from . import zgrab2

dimse_scan_response = SubRecord(
    {
        "result": SubRecord(
            {
                "established": Boolean(),
                "called_ae": String(),
                "calling_ae": String(),
                "implementation_class_uid": String(),
                "implementation_version": String(),
                "max_pdu_length": Unsigned32BitInteger(),
                "accepted_transfer_syntax": String(),
                "verification_accepted": Boolean(),
                "echo_status": Unsigned16BitInteger(),
                "tls": zgrab2.tls_log,
                "rejected": Boolean(),
                "aborted": Boolean(),
                "reject_result": Unsigned8BitInteger(),
                "reject_source": Unsigned8BitInteger(),
                "reject_reason": Unsigned8BitInteger(),
                "reject_detail": String(),
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-dimse", dimse_scan_response)

zgrab2.register_scan_response_type("dimse", dimse_scan_response)

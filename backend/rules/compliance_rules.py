COMPLIANCE_RULES = {

    # =========================================================
    # CIS
    # =========================================================

    "CIS": [

        {
            "id": "CIS-01",
            "name": "Use SSH Version 2",
            "severity": "HIGH",
            "parameter": "ssh_version",
            "expected_value": 2,
            "description": "Administrative remote access should use SSH version 2.",
            "remediation": "Configure SSH version 2 and disable older SSH versions."
        },

        {
            "id": "CIS-02",
            "name": "Disable Telnet",
            "severity": "HIGH",
            "parameter": "telnet_enabled",
            "expected_value": False,
            "description": "Telnet should be disabled because it provides insecure remote administration.",
            "remediation": "Disable Telnet and use SSH for administrative access."
        },

        {
            "id": "CIS-03",
            "name": "Disable Unsecured HTTP Management",
            "severity": "HIGH",
            "parameter": "http_enabled",
            "expected_value": False,
            "description": "Unencrypted HTTP management should be disabled.",
            "remediation": "Disable HTTP management and use HTTPS."
        },

        {
            "id": "CIS-04",
            "name": "Enable Logging",
            "severity": "MEDIUM",
            "parameter": "logging_enabled",
            "expected_value": True,
            "description": "Security-relevant system activity should be logged.",
            "remediation": "Enable system logging and configure appropriate log storage."
        },

        {
            "id": "CIS-05",
            "name": "Avoid Plaintext Password",
            "severity": "CRITICAL",
            "parameter": "plaintext_password",
            "expected_value": False,
            "description": "Administrative credentials should not be stored using plaintext password configuration.",
            "remediation": "Replace plaintext passwords with secure credential mechanisms."
        },

        {
            "id": "CIS-06",
            "name": "Enable AAA",
            "severity": "HIGH",
            "parameter": "aaa_enabled",
            "expected_value": True,
            "description": "Authentication and authorization should be centrally controlled.",
            "remediation": "Enable AAA and configure appropriate authentication and authorization policies."
        },

        {
            "id": "CIS-07",
            "name": "Secure Network Management",
            "severity": "HIGH",
            "parameter": "snmp_v1_v2_detected",
            "expected_value": False,
            "description": "Legacy SNMP versions should not be used for secure network management.",
            "remediation": "Migrate network management to SNMPv3."
        }

    ],


    # =========================================================
    # NIST
    # =========================================================

    "NIST": [

        {
            "id": "NIST-AC-01",
            "name": "Access Control",
            "severity": "HIGH",
            "parameter": "aaa_enabled",
            "expected_value": True,
            "description": "Network administrative access should use controlled authentication and authorization.",
            "remediation": "Enable AAA and enforce centralized access control."
        },

        {
            "id": "NIST-CM-01",
            "name": "Secure Configuration",
            "severity": "HIGH",
            "parameter": "telnet_enabled",
            "expected_value": False,
            "description": "Insecure administrative services should be disabled.",
            "remediation": "Disable Telnet and use secure remote administration."
        },

        {
            "id": "NIST-AU-01",
            "name": "Audit Logging",
            "severity": "HIGH",
            "parameter": "logging_enabled",
            "expected_value": True,
            "description": "Security-relevant events should be recorded for auditing.",
            "remediation": "Enable logging and retain security-relevant events."
        },

        {
            "id": "NIST-AU-02",
            "name": "Remote Audit Storage",
            "severity": "MEDIUM",
            "parameter": "remote_logging_enabled",
            "expected_value": True,
            "description": "Logs should be forwarded to an appropriate centralized logging destination.",
            "remediation": "Configure remote syslog or an equivalent centralized logging system."
        },

        {
            "id": "NIST-IA-01",
            "name": "Strong Authentication",
            "severity": "HIGH",
            "parameter": "aaa_enabled",
            "expected_value": True,
            "description": "Administrative access should use strong authentication controls.",
            "remediation": "Configure AAA with an appropriate authentication service."
        },

        {
            "id": "NIST-SC-01",
            "name": "Protect Communications",
            "severity": "HIGH",
            "parameter": "encryption_configured",
            "expected_value": True,
            "description": "Sensitive communications should use approved cryptographic protection.",
            "remediation": "Configure secure encrypted communication protocols."
        }

    ],


    # =========================================================
    # STIG
    # =========================================================

    "STIG": [

        {
            "id": "STIG-NET-01",
            "name": "Disable Telnet",
            "severity": "HIGH",
            "parameter": "telnet_enabled",
            "expected_value": False,
            "description": "Unsecure remote administration services should be disabled.",
            "remediation": "Disable Telnet and use SSH."
        },

        {
            "id": "STIG-NET-02",
            "name": "Use Secure Remote Administration",
            "severity": "HIGH",
            "parameter": "ssh_version",
            "expected_value": 2,
            "description": "Remote administrative access should use a secure SSH implementation.",
            "remediation": "Configure SSH version 2."
        },

        {
            "id": "STIG-NET-03",
            "name": "Enable Audit Logging",
            "severity": "HIGH",
            "parameter": "logging_enabled",
            "expected_value": True,
            "description": "Administrative and security-relevant activity must be auditable.",
            "remediation": "Enable security logging and auditing."
        },

        {
            "id": "STIG-NET-04",
            "name": "Centralized Logging",
            "severity": "MEDIUM",
            "parameter": "remote_logging_enabled",
            "expected_value": True,
            "description": "Security logs should be forwarded to a centralized logging capability.",
            "remediation": "Configure centralized remote logging."
        },

        {
            "id": "STIG-NET-05",
            "name": "Protected Credentials",
            "severity": "CRITICAL",
            "parameter": "plaintext_password",
            "expected_value": False,
            "description": "Credentials must not be exposed through insecure password configuration.",
            "remediation": "Remove plaintext credentials and use secure authentication mechanisms."
        }

    ],


    # =========================================================
    # ISO 27001
    # =========================================================

    "ISO": [

        {
            "id": "ISO-A.05",
            "name": "Access Control",
            "severity": "HIGH",
            "parameter": "aaa_enabled",
            "expected_value": True,
            "description": "Access to network administration should be appropriately controlled.",
            "remediation": "Implement strong authentication and authorization controls."
        },

        {
            "id": "ISO-A.08",
            "name": "Secure Authentication",
            "severity": "HIGH",
            "parameter": "ssh_version",
            "expected_value": 2,
            "description": "Administrative access should use secure authentication and communication mechanisms.",
            "remediation": "Use SSH version 2 for remote administration."
        },

        {
            "id": "ISO-A.08-LOG",
            "name": "Security Event Logging",
            "severity": "MEDIUM",
            "parameter": "logging_enabled",
            "expected_value": True,
            "description": "Relevant security events should be logged and monitored.",
            "remediation": "Enable security event logging."
        },

        {
            "id": "ISO-A.08-NET",
            "name": "Network Security",
            "severity": "HIGH",
            "parameter": "telnet_enabled",
            "expected_value": False,
            "description": "Network services should be protected against unauthorized access.",
            "remediation": "Disable insecure network administration protocols."
        },

        {
            "id": "ISO-A.08-CRYPT",
            "name": "Cryptographic Protection",
            "severity": "HIGH",
            "parameter": "encryption_configured",
            "expected_value": True,
            "description": "Cryptographic controls should protect sensitive communications.",
            "remediation": "Configure appropriate encryption mechanisms."
        }

    ]

}
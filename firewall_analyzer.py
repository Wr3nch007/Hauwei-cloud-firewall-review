import pandas as pd

def analyze_firewall(file_path):

    df = pd.read_excel(file_path)

    findings = []
    sno = 1

    def add(rule_id, vuln, severity, rec, ref):
        nonlocal sno

        findings.append({
            "S.No": sno,
            "Rule ID": rule_id,
            "Vulnerability": vuln,
            "Severity": severity,
            "Recommendation": rec,
            "Reference": ref
        })

        sno += 1


    for index, row in df.iterrows():

        rule_id = row.get("SN", index+1)
        source = str(row.get("Source","")).lower()
        destination = str(row.get("Destination","")).lower()
        ports = str(row.get("Destination Port Range","")).lower()
        protocol = str(row.get("protocol","")).lower()
        action = str(row.get("Action","")).lower()
        description = str(row.get("Description","")).strip()


        if "0.0.0.0/0" in source and "0.0.0.0/0" in destination and action == "allow":
            add(
                rule_id,
                "Any-to-Any firewall rule detected",
                "Critical",
                "Restrict source and destination addresses to required networks only.",
                "CIS Firewall Benchmark / NIST SP 800-41"
            )


        if "0.0.0.0/0" in source and action == "allow":
            add(
                rule_id,
                "Rule allows traffic from the internet",
                "High",
                "Limit the source IP range to trusted networks.",
                "ISO 27001 A.13.1"
            )


        if protocol in ["ssh","rdp","ftp","telnet"] and "0.0.0.0/0" in source:
            add(
                rule_id,
                f"{protocol.upper()} service exposed to internet",
                "High",
                f"Restrict {protocol.upper()} access to administrative IPs only.",
                "NIST SP 800-41"
            )


        if ports in ["any","1-65535"]:
            add(
                rule_id,
                "Overly permissive port range",
                "Medium",
                "Restrict firewall rule to only required ports.",
                "PCI DSS 1.2.1"
            )


        if description == "" or description.lower() == "nan":
            add(
                rule_id,
                "Firewall rule missing description",
                "Low",
                "Add rule description and business justification.",
                "ISO 27001 A.12.1"
            )


    result = pd.DataFrame(findings)

    return result

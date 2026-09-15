# Nmap XML Inventory

Convert existing Nmap XML into a JSON inventory of open services. The script does not scan networks or contact targets.

```bash
python3 portfolio/analyze.py nmap portfolio/nmap-inventory/scan.xml
```

The included XML is a synthetic fixture, not a real scan. Expected result: SSH/22 and HTTPS/443 on documentation address 192.0.2.10; closed Telnet/23 is excluded. Output is in `expected.json`.

## Defensive use
Compare open services with an approved asset baseline. Confirm ownership and intended exposure before recommending restrictions. An open port is not proof of a vulnerability; service labels from scanning can be incomplete or inaccurate.

## Limitations
No CVE mapping, vulnerability exploitation, OS detection or historical diffing is performed. XML with DTD/entity declarations is rejected. Use small local reports; this teaching parser loads the entire input into memory.

## Interview walkthrough
Explain open versus filtered versus closed states, scope authorization, and how you would validate an unexpected exposed service.

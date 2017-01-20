# Beaver Service

This service performs hash lookups against the CCIRC Malware Database.

**NOTE**: This service **requires** you to have access to CCIRC Malware database. It is **not** preinstalled during a default installation

## Execution

This service works by querying CCIRC Malware database via API or with direct database access to see if the file that you are submitting has already been seen by CCIRC Malware analysis team. It will then pull dynamic analysis information about the malware as well as AVs results and domain for it.

## Access to CCIRC Malware Database

CCIRC Malware database is not available for public consumption. It is right now restricted to government of Canada departments only. If your organization does not fit this profile, don't bother asking about it.
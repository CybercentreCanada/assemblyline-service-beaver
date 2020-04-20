# Beaver Service

This service performs hash lookups against the CCIRC Malware Database.

**NOTE**: This service **requires** you to have access to the CCIRC Malware database. It is **not** preinstalled during a default installation

## Execution

This service works by querying the CCIRC Malware database via API or with direct database access to see if the file that you are submitting has already been seen by the CCIRC Malware analysis team. It will then pull dynamic analysis information about the malware as well as AV results and domains.


## Access to CCIRC Malware Database

The CCIRC Malware database is not available for public consumption. It is currently restricted to government of Canada departments only. If your organization does not fit this profile, this service will be unavailable.
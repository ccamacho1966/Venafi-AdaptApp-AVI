# Venafi-AdaptApp-AVI
Adaptable application driver for Avi Networks (https://avinetworks.com/software-load-balancer/) - fork of Avi Networks developed original driver.

## Description
This adaptable application uses Avi Network's API to discover and manage certificates linked to virtual services. This was forked from an earlier driver released by Avi Networks with multiple bug fixes mostly related to discovery.

## Installation
Upload the adaptable log driver file 'Avi-Networks.ps1' to all Venafi servers.
The default folder location would be 'C:\Program Files\Venafi\Scripts\AdaptableApp'.

## Usage

### Credentials
Pass API credentials to the driver as a 'Username Credential' and linked either as the 'Device Credential' or 'Application Credential'.

### Policy-Level Application Fields
Debug Avi Driver (Yes/No) - Allows you to log debug info for all applications under this policy folder.

### Application Configuration
Create a new device pointing to the Avi cluster FQDN or IP address.
You can either run an onboard discovery to populate all existing applications or manually create each application individually. If creating applications manually, you must supply the names for the virtual service and tenant. Discovery will populate these fields automatically.
At this level, setting 'Debug Avi Driver' and 'Enable Debug Logging' function identically and will trigger log creation for this application.

## Support
Please report issues through github. This driver is still being actively used and supported.

## Roadmap
Functionally this should be 'complete' for discovery and management purposes.

## Contributing
Assistance is always welcome. I'm not really a programmer. I just play one on community forums.

## Authors and acknowledgment
Just me for the moment. Buyer Beware.

<#
//----------------------------------------------------------------------- 
// Avi-Networks.ps1
//
// Original script developed by Avi Networks
// Based on a sample script provided by Venafi
// This version is maintained by Christopher Camacho
//
// This script is provided "as is" without warranty of any kind.
//----------------------------------------------------------------------- 

Modifications to Avi Networks driver coding:
- changed naming convention for discovered certificates to "vs_name (tenant_name)" to better avoid collisions
- extract and save certificate name for proper validation after discovery ... bad bug!
- fix get-allvs to actually return more than 25 virtual services by supporting pagination ... another bad bug!
- logging has been extensively overhauled to utilize better separation of logs, more useful log filenames,
-- and an end to multiple discovery processes writing into the same logs which greatly reduces their usefulness.
- reworked login and rest call functions to keep CSRF token properly updated
- cleaned up header management to keep functions smaller and datasets consistent
- extract certificate did not actually extract the in-use certificate therefore validation results could not
-- be relied on. changes to the virtual service can easily be missed if the certificate on disk doesn't change
-- as the only thing checked was the actual certificate file/entry. the virtual service was not checked at all.

<field name>|<label text>|<flags>

Bit 1 = Enabled
Bit 2 = Policyable
Bit 3 = Mandatory

-----BEGIN FIELD DEFINITIONS-----
Text1|Virtual Service|100
Text2|Tenant|100
Text3|Not Used|000
Text4|Not Used|000
Text5|Not Used|000
Option1|Debug Avi Driver|110
Option2|Not Used|000
Passwd|Not Used|000
-----END FIELD DEFINITIONS-----
#>

$Script:AdaptableAppVer = '202507011619'
$Script:AdaptableAppDrv = 'Avi-Networks'

# need the following to interface with an untrusted certificate
Add-Type -TypeDefinition @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

<##################################################################################################
.NAME
    Prepare-KeyStore
.DESCRIPTION
    Remotely create and/or verify keystore on the hosting platform.  Remote generation is considered UNSUPPORTED if this
    function is ommitted or commented out.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions
        HostAddress : a string containing the hostname or IP address specified by the device object
        TcpPort : an integer value containing the TCP port specified by the application object
        UserName : a string containing the username portion of the credential assigned to the device or application object
        UserPass : a string containing the password portion of the credential assigned to the device or application object
        UserPrivKey : the non-encrypted PEM of the private key credential assigned to the device or application object
        AppObjectDN : a string containing the TPP distiguished name of the calling application object
        AssetName : a string containing a Venafi standard auto-generated name that can be used for provisioning (<Common Name>-<ValidTo as YYMMDD>-<Last 4 of SerialNum>)
        VarText1 : a string value for the text custom field defined by the header at the top of this script
        VarText2 : a string value for the text custom field defined by the header at the top of this script
        VarText3 : a string value for the text custom field defined by the header at the top of this script
        VarText4 : a string value for the text custom field defined by the header at the top of this script
        VarText5 : a string value for the text custom field defined by the header at the top of this script
        VarBool1 : a boolean value for the yes/no custom field defined by the header at the top of this script (true|false)
        VarBool2 : a boolean value for the yes/no custom field defined by the header at the top of this script (true|false)
        VarPass : a string value for the password custom field defined by the header at the top of this script
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
##################################################################################################>
function Prepare-KeyStore
{
    # This line tells VS Code to not flag this function's name as a "problem"
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseApprovedVerbs', '', Justification='Forced by Venafi', Scope='function')]
    
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable] $General
    )

    return @{ Result='NotUsed' }
}


<##################################################################################################
.NAME
    Generate-KeyPair
.DESCRIPTION
    Remotely generates a public-private key pair on the hosting platform.  Remote generation is 
    considered UNSUPPORTED if this function is ommitted or commented out.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.PARAMETER Specific
    A hashtable containing the specific set of variables needed by this function
        KeySize : the integer key size to be used when creating a key pair
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
##################################################################################################>
function Generate-KeyPair
{
    # This line tells VS Code to not flag this function's name as a "problem"
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseApprovedVerbs', '', Justification='Forced by Venafi', Scope='function')]
    
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable] $General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable] $Specific
    )
   
    return @{ Result='NotUsed' }
}


<##################################################################################################
.NAME
    Generate-CSR
.DESCRIPTION
    Remotely generates a CSR on the hosting platform.  Remote generation is considered UNSUPPORTED
    if this function is ommitted or commented out.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.PARAMETER Specific
    A hashtable containing the specific set of variables needed by this function
        SubjectDN : the requested subject distiguished name as a hashtable; OU is a string array; all others are strings
        SubjAltNames : hashtable keyed by SAN type; values are string arrays
        KeySize : the integer key size to be used when creating a key pair
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
        Pkcs10 : a string representation of the CSR in PKCS#10 format
##################################################################################################>
function Generate-CSR
{
    # This line tells VS Code to not flag this function's name as a "problem"
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseApprovedVerbs', '', Justification='Forced by Venafi', Scope='function')]
    
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable] $General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable] $Specific
    )

    $General | Initialize-VenDebugLog

	if (-not $($Specific.SubjectDn.CN)) {
        throw "Common Name is required by Avi Vantage for remotely generated CSRs."
    }

    # Build the subject structure for a remotely generated CSR
    $subject = @{ "common_name" = $($Specific.SubjectDn.CN) }
    if ($Specific.SubjectDn.O)  { $subject.Add( "organization",      $Specific.SubjectDn.O )     }
    # only one OU is currently supported so we always use the first if there are many
    if ($Specific.SubjectDn.OU) { $subject.Add( "organization_unit", $Specific.SubjectDn.OU[0] ) }
    if ($Specific.SubjectDn.L)  { $subject.Add( "locality",          $Specific.SubjectDn.L )     }
    if ($Specific.SubjectDn.ST) { $subject.Add( "state",             $Specific.SubjectDn.ST )    }
    if ($Specific.SubjectDn.C)  { $subject.Add( "country",           $Specific.SubjectDn.C )     }

    $sans_dns = @() + $($Specific.SubjAltNames.DNS | Where-Object {$_})  # an array of DNS Subject Alternative Names, possibly empty

    # Create an API session with the Avi controller
    $AviSession = $General | New-AviApiSession

    $body = @{
        "name"        = $General.AssetName;
        "certificate" = @{
            "self_signed"       = $false;
            "subject"           = $subject;
            "subject_alt_names" = $sans_dns;
        };
        "type"        = "SSL_CERTIFICATE_TYPE_VIRTUALSERVICE";
        "key_params"  = @{
            "algorithm"         = "SSL_KEY_ALGORITHM_RSA";
            "rsa_params"        = @{ "key_size" = $("SSL_KEY_$($Specific.KeySize)_BITS") }
        }
    } | ConvertTo-Json

    try {
        Write-VenDebugLog "Creating new remotely generated CSR for '$($General.AssetName)'"
        $url = "https://$($General.HostAddress)/api/sslkeyandcertificate"
        $AviReply = Invoke-AviRestApi -Uri $url -Method Post -Body $body -WebSession $AviSession
        $CsrUuid  = $AviReply.uuid

        Write-VenDebugLog "Downloading CSR from Avi controller (UUID: $($CsrUuid))"
        $url = "https://$($General.HostAddress)/api/sslkeyandcertificate/$($CsrUuid)"
        $AviReply = Invoke-AviRestApi -Uri $url -Method Get -WebSession $AviSession
    } catch {
        Write-VenDebugLog "API ERROR (Generate CSR): $(Select-ErrorMessage($_.Exception))" -ThrowException
    }

    # Attempt to be nice and log out of the API
    $AviSession | Remove-AviApiSession

    Write-VenDebugLog 'Returning control to Venafi'
    $CsrText  = $AviReply.certificate.certificate_signing_request

    return @{
        Result = 'Success'
        Pkcs10 = $CsrText
    }
}


<##################################################################################################
.NAME
    Install-Chain
.DESCRIPTION
    Installs the certificate chain on the hosting platform.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.PARAMETER Specific
    A hashtable containing the specific set of variables needed by this function
        ChainPem : all chain certificates concatentated together one after the other
        ChainPkcs7 : byte array PKCS#7 collection that includes all chain certificates
.NOTES
    Returns...
        Result : 'Success', 'AlreadyInstalled' or 'NotUsed' to indicate the non-error completion state
##################################################################################################>
function Install-Chain
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable] $General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable] $Specific
    )

    $General | Initialize-VenDebugLog

    # Create an API session with the Avi controller
    $AviSession = $General | New-AviApiSession

    try {
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        $chain.Import($Specific.ChainPkcs7)
        foreach ($cert in $chain) {
            $is_installed = $false
            $cacert_name = $cacert_basename = ($cert | Get-CACertName)
            for ($i=0; $i -lt 10; $i++) {
                Write-VenDebugLog "Preparing to upload CA certificate: [$($cacert_name)]"

                # check to see if a certificate already exists by the name
                $url = "https://$($General.HostAddress)/api/sslkeyandcertificate?name=$($cacert_name)&export_key=false"
                $AviReply = Invoke-AviRestApi -Uri $url -Method Get -WebSession $AviSession

                if ($AviReply.Count -ne 0) {
                    # name collision, is it the same cert?
                    $pem = ($AviReply.results.certificate.certificate).Replace("-----BEGIN CERTIFICATE-----","").Replace("-----END CERTIFICATE-----","")
                    $cert_existing = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                    $cert_existing.Import([Convert]::FromBase64String($pem))

                    if ($cert_existing.Equals($cert)) {
                        # This certificate is already installed
                        Write-VenDebugLog "CA certificate '$($cacert_name)' has already been installed."
                        $is_installed = $true
                        break
                    } else {
                        # append an integer and test that name for uniqueness
                        Write-VenDebugLog "CA certificate '$($cacert_name)' exists, but does not match!"
                        $cacert_name = "$($cacert_basename)_$($idx)"
                    }
                } else {
                    # install the CA certificate
                    $pem = [Convert]::ToBase64String($cert.RawData, [System.Base64FormattingOptions]::InsertLineBreaks)
                    $url = "https://$($General.HostAddress)/api/sslkeyandcertificate"
                    $body = @{
                        "certificate" = @{ "certificate"="-----BEGIN CERTIFICATE-----`n$($pem)`n-----END CERTIFICATE-----" }
                        "name"        = $cacert_name
                        "type"        = "SSL_CERTIFICATE_TYPE_CA"
                    } | ConvertTo-Json
                    Invoke-AviRestApi -Uri $url -Method Post -Body $body -WebSession $AviSession | Out-Null
                    Write-VenDebugLog "CA certificate '$($cacert_name)' has been uploaded."
                    $is_installed = $true
                    break
                }
            }
            if (-not $is_installed) {
                "Automatic name conflict resolution threshold was exceeded for '$($cacert_basename)'" | Write-VenDebugLog -ThrowException
            }
        }
    } catch {
        throw Select-ErrorMessage($_.Exception)
    }

    # Attempt to be nice and log out of the API
    $AviSession | Remove-AviApiSession

    Write-VenDebugLog 'CA chain installed - Returning control to Venafi'
    return @{ Result='Success' }
}


<##################################################################################################
.NAME
    Install-PrivateKey
.DESCRIPTION
    Installs the private key on the hosting platform.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.PARAMETER Specific
    A hashtable containing the specific set of variables needed by this function
        PrivKeyPem : the non-encrypted private key in RSA Base64 PEM format
        PrivKeyPemEncrypted : the password encrypted private key in RSA Base64 PEM format
        EncryptPass : the string password that was used to encrypt the private key and PKCS#12 keystore
.NOTES
    Returns...
        Result : 'Success', 'AlreadyInstalled' or 'NotUsed' to indicate the non-error completion state
        AssetName : (optional) the base name used to reference the private key as it was installed on the device; if not supplied the auto-generated name is assumed
##################################################################################################>
function Install-PrivateKey
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable] $General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable] $Specific
    )

    return @{ Result='NotUsed' }
}


<##################################################################################################
.NAME
    Install-Certificate
.DESCRIPTION
    Installs the certificate on the hosting platform.  May optionally be used to also install the private key and chain.
    Implementing logic for this function is REQUIRED.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.PARAMETER Specific
    A hashtable containing the specific set of variables needed by this function
        CertPem : the X509 certificate to be provisioned in Base64 PEM format
        PrivKeyPem : the non-encrypted private key in RSA Base64 PEM format
        PrivKeyPemEncrypted : the password encrypted private key in RSA Base64 PEM format
        ChainPem : all chain certificates concatentated together one after the other
        ChainPkcs7 : byte array PKCS#7 collection that includes all chain certificates
        Pkcs12 : byte array PKCS#12 collection that includes certificate, private key, and chain
        EncryptPass : the string password that was used to encrypt the private key and PKCS#12 keystore
.NOTES
    Returns...
        Result : 'Success', 'AlreadyInstalled' or 'NotUsed' to indicate the non-error completion state (may only be 'NotUsed' if Install-PrivateKey did not return 'NotUsed')
        AssetName : (optional) the base name used to reference the certificate as it was installed on the device; if not supplied the auto-generated name is assumed
##################################################################################################>
function Install-Certificate
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable] $General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable] $Specific
    )

    $General | Initialize-VenDebugLog

    # Create an API session with the Avi controller
    $AviSession = $General | New-AviApiSession

    try {
        Write-VenDebugLog "Preparing to upload certificate: [$($General.AssetName)]"

        $cert = $Specific.CertPem
        $key  = $Specific.PrivKeyPem
        if ($key) { # this is central generation
            # Check to see if a certificate already exists by the name
            $url = "https://$($General.HostAddress)/api/sslkeyandcertificate?name=$($General.AssetName)&export_key=false"
            $AviReply = Invoke-AviRestApi -Uri $url -Method Get -WebSession $AviSession

            if ($AviReply.Count) { # name collision, is it the same cert?
                $pem = $cert.Replace("-----BEGIN CERTIFICATE-----","").Replace("-----END CERTIFICATE-----","")
                $cert_installing = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                $cert_installing.Import([Convert]::FromBase64String($pem))

                $pem = $AviReply.results.certificate.certificate
                $pem = $pem.Replace("-----BEGIN CERTIFICATE-----","").Replace("-----END CERTIFICATE-----","")
                $cert_existing = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                $cert_existing.Import([Convert]::FromBase64String($pem))

                if ($cert_existing.Equals($cert_installing)) { # Are these the same certificate?
                    Write-VenDebugLog 'Certificate is already installed - Returning control to Venafi'
                    return @{ Result='AlreadyInstalled' }
                } else {
                    "A different certificate already exists with the name '$($General.AssetName)'" | Write-VenDebugLog -ThrowException
                }
            }

            $url = "https://$($General.HostAddress)/api/sslkeyandcertificate"            
            $body = @{
	            "certificate" = @{ "certificate" = $cert }
                "key"         = $key
	            "name"        = $General.AssetName
                "type"        = 'SSL_CERTIFICATE_TYPE_VIRTUALSERVICE'
            } | ConvertTo-Json

            # Upload the certificate
            Invoke-AviRestApi -Uri $url -Method Post -Body $body -WebSession $AviSession | Out-Null
            Write-VenDebugLog "Certificate has been uploaded as '$($General.AssetName)' - Returning control to Venafi"
        } else { # this is remote generation
            # Lookup the CSR
            Write-VenDebugLog "Searching for remotely generated CSR for '$($General.AssetName)'"
            $url = "https://$($General.HostAddress)/api/sslkeyandcertificate?name=$($General.AssetName)&export_key=false"
            $AviReply = Invoke-AviRestApi -Uri $url -Method Get -WebSession $AviSession

            if ($AviReply.Count) { # found it
                if (-not $AviReply.results.certificate.certificate) {
                    # install the certificate
                    $url = $AviReply.results.url
					$AviReply.results.certificate | Add-Member -MemberType NoteProperty -Name 'certificate' -Value $cert
                    $body = $AviReply.results | ConvertTo-Json
                    Invoke-AviRestApi -Uri $url -Method Put -Body $body -WebSession $AviSession | Out-Null

                    Write-VenDebugLog "Certificate has been uploaded as '$($General.AssetName)' - Returning control to Venafi"
                } else {
                    "A different certificate is already installed as '$($General.AssetName)'" | Write-VenDebugLog -ThrowException
                }
            } else {
                "Remotely generated CSR was not found for '$($General.AssetName)'" | Write-VenDebugLog -ThrowException
            }
        }
    } catch {
        "Unexpected Error: $(Select-ErrorMessage($_.Exception))" | Write-VenDebugLog -ThrowException
    }

    # Attempt to be nice and log out of the API
    $AviSession | Remove-AviApiSession

    return @{ Result='Success' }
}


<##################################################################################################
.NAME
    Update-Binding
.DESCRIPTION
    Binds the installed certificate with the consuming application or service on the hosting platform
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
##################################################################################################>
function Update-Binding
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable] $General
    )

    $General | Initialize-VenDebugLog

    # Create an API session with the Avi controller
    $AviSession = $General | New-AviApiSession

    $VirtualServiceName = $General.VarText1

    # Get Virtual Service Configuration
    Write-VenDebugLog "Retrieving configuration for Virtual Service '$($VirtualServiceName)'"
    try {
        $url = "https://$($General.HostAddress)/api/virtualservice?name=$($VirtualServiceName)"
        $AviReply = Invoke-AviRestApi -Uri $url -Method Get -WebSession $AviSession
    } catch {
        "API ERROR (Find Virtual Service): $(Select-ErrorMessage($_.Exception))" | Write-VenDebugLog -ThrowException
    }

    if (-not $AviReply.Count) {
        # Virtual Service was not found
        "Virtual Service '$($VirtualServiceName)' was not found." | Write-VenDebugLog -ThrowException
    }

    # Save the existing Virtual Service configuration for later
    $VirtualServiceConfig = $AviReply.results[0]
    $VirtualServiceUUID   = $VirtualServiceConfig.uuid

    Write-VenDebugLog "Looking up certificate file '$($General.AssetName)'"
    try {
        # Search the Avi controller for the Certificate UUID
        $url = "https://$($General.HostAddress)/api/sslkeyandcertificate?name=$($General.AssetName)"
        $AviReply = Invoke-AviRestApi -Uri $url -Method Get -WebSession $AviSession
    } catch {
        "API ERROR (Find Certificate): $(Select-ErrorMessage($_.Exception))" | Write-VenDebugLog -ThrowException
    }

    if (-not $AviReply.Count) {
        # Certificate was not found
        "Certificate with asset name '$($General.AssetName)' was not found." | Write-VenDebugLog -ThrowException
    }

    $CertificateRef = $AviReply.results[0].url

    # Create the updated configuration structure
    $body = $VirtualServiceConfig
    $body.ssl_key_and_certificate_refs = @( $CertificateRef )
    $body = $body | ConvertTo-Json -Depth 100

    Write-VenDebugLog "Binding certificate '$($General.AssetName)' to virtual service '$($VirtualServiceName)'"
    try {
        # Associate certificate with virtual service instance
        $url = "https://$($General.HostAddress)/api/virtualservice/$($VirtualServiceUUID)"
        Invoke-AviRestApi -Uri $url -Method Put -Body $body -WebSession $AviSession | Out-Null
    } catch {
        "API ERROR (Update Virtual Service): $(Select-ErrorMessage($_.Exception))" | Write-VenDebugLog -ThrowException
    }

    # Attempt to be nice and log out of the API
    $AviSession | Remove-AviApiSession

    Write-VenDebugLog "Virtual Service has been updated - Returning control to Venafi"
    return @{ Result='Success' }
}

<##################################################################################################
.NAME
    Activate-Certificate
.DESCRIPTION
    Performs any post-installation operations necessary to make the certificate active (such as restarting a service)
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
##################################################################################################>
function Activate-Certificate
{
    # This line tells VS Code to not flag this function's name as a "problem"
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseApprovedVerbs', '', Justification='Forced by Venafi', Scope='function')]
    
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable] $General
    )
    
    return @{ Result='NotUsed' }
}


<##################################################################################################
.NAME
    Extract-Certificate
.DESCRIPTION
    Extracts the active certificate from the hosting platform.  If the platform does not provide a method for exporting the
    raw certificate then it is sufficient to return only the Serial and Thumprint.  This function is REQUIRED.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
        CertPem : the extracted X509 certificate referenced by AssetName in Base64 PEM format
        Serial : the serial number of the X509 certificate refernced by AssetName
        Thumbprint : the SHA1 thumprint of the X509 certificate referenced by AssetName
##################################################################################################>
function Extract-Certificate
{
    # This line tells VS Code to not flag this function's name as a "problem"
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseApprovedVerbs', '', Justification='Forced by Venafi', Scope='function')]
    
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable] $General
    )

    # The original logic in use for this function was wrong on a fundamental level.
    # It only checked to see if the file existed and returned its contents.
    # It did not validate the actual VS configuration or return the actual certificate in use.
    # This defeats the entire intent of doing proper installation validation.
    #
    # Issue originally reported by Van Dunn on 26-June-2025

    $General | Initialize-VenDebugLog

    # Create an API session with the Avi controller
    $AviSession = $General | New-AviApiSession

    # Pull the Virtual Service configuration
    $VirtualServiceName = $General.VarText1
    Write-VenDebugLog "Retrieving configuration for Virtual Service '$($VirtualServiceName)'"
    try {
        # Search the Avi controller for the Virtual Service
        $url = "https://$($General.HostAddress)/api/virtualservice?name=$($VirtualServiceName)"
        $AviReply = Invoke-AviRestApi -Uri $url -Method Get -WebSession $AviSession
    } catch {
        "API ERROR (Find Virtual Service): $(Select-ErrorMessage($_.Exception))" | Write-VenDebugLog -ThrowException
    }

    if (-not $AviReply.Count) {
        "Virtual Service '$($VirtualServiceName)' was not found." | Write-VenDebugLog -ThrowException
    }

    # Save the existing Virtual Service configuration for later
    $VirtualServiceConfig = $AviReply.results[0]

    # Confirm the Virtual Service is encrypted. If not, throw a failure.
    if (-not $VirtualServiceConfig.ssl_key_and_certificate_refs) {
        "Virtual Service '$($VirtualServiceName)' does not have a certificate defined (unencrypted)" | Write-VenDebugLog -ThrowException
    }

    Write-VenDebugLog "Retrieving certificate for Virtual Service '$($VirtualServiceName)'"
    # Pull the Public Certificate attached to the Virtual Service
    try {
        $AviReply = Invoke-AviRestApi -Uri $VirtualServiceConfig.ssl_key_and_certificate_refs[0] -Method Get -WebSession $AviSession
    } catch {
        "API ERROR (Extract Certificate): $(Select-ErrorMessage($_.Exception))" | Write-VenDebugLog -ThrowException
    }

    if (-not $AviReply.certificate) {
        "Certificate for Virtual Service '$($VirtualServiceName)' was not found." | Write-VenDebugLog -ThrowException
    }

    $CertFileName = $AviReply.name
    $CertInUse    = $AviReply.certificate
    $PEM          = $CertInUse.certificate
    $idx          = $CertInUse.fingerprint.IndexOf('=')
    $Thumbprint   = $CertInUse.fingerprint.Remove(0,$idx+1).Replace(":","").ToLower().Trim()
    $SerialNumber = "{0:x}" -f [bigint]$($CertInUse.serial_number)

    if ($CertFileName -ne $General.AssetName) {
        Write-VenDebugLog "WARNING: Expected filename '$($General.AssetName)' but got filename '$($CertFileName)' instead"
    }

    # Return the public certificate, thumbprint, and serial number for the certificate actually in use
    Write-VenDebugLog "Certificate Asset Name:    $($General.AssetName)"
    Write-VenDebugLog "Certificate Serial Number: $($SerialNumber)"
    Write-VenDebugLog "Certificate Thumbprint:    $($Thumbprint)"
    Write-VenDebugLog "Certificate Valid Until:   $($CertInUse.not_after) UTC"

    # Attempt to be nice and log out of the API
    $AviSession | Remove-AviApiSession

    Write-VenDebugLog "Certificate extracted successfully - Returning control to Venafi"
    return @{
        Result     = 'Success'
        CertPem    = $PEM
        Serial     = $SerialNumber
        Thumbprint = $Thumbprint
    }
}


<##################################################################################################
.NAME
    Extract-PrivateKey
.DESCRIPTION
    Extracts the private key associated with the certificate from the hosting platform
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.PARAMETER Specific
    A hashtable containing the specific set of variables needed by this function
        EncryptPass : the string password to use when encrypting the private key
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
        PrivKeyPem : the extracted private key in RSA Base64 PEM format (encrypted or not)
##################################################################################################>
function Extract-PrivateKey
{
    # This line tells VS Code to not flag this function's name as a "problem"
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseApprovedVerbs', '', Justification='Forced by Venafi', Scope='function')]
    
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable] $General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable] $Specific
    )

    $General | Initialize-VenDebugLog

    # Create an API session with the Avi controller
    $AviSession = $General | New-AviApiSession

    try {
        # Search the Avi controller for the certificate
        $url = "https://$($General.HostAddress)/api/sslkeyandcertificate?name=$($General.AssetName)&export_key=true"
        $AviReply = Invoke-AviRestApi -Uri $url -Method Get -WebSession $AviSession
    } catch {
        "API ERROR (Extract Private Key): $(Select-ErrorMessage($_.Exception))" | Write-VenDebugLog -ThrowException
    }

    if (-not $AviReply.Count) {
        # Private key for certificate was not found
        "Private key for certificate with asset name '$($General.AssetName)' was not found" | Write-VenDebugLog -ThrowException
    }

    # Private key for certificate has been found - Parse results and return data to Venafi
    $PrivateKey = $AviReply.results.key

    # Attempt to be nice and log out of the API
    $AviSession | Remove-AviApiSession

    Write-VenDebugLog "Private key extracted successfully - Returning control to Venafi"
    return @{
        Result        = 'Success'
        PrivateKeyPem = $PrivateKey
    }
}


<##################################################################################################
.NAME
    Remove-Certificate
.DESCRIPTION
    Removes an existing certificate (or private key) from the device.  Only implement the body of 
    this function if TPP can/should remove old generations of the same asset.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.PARAMETER Specific
    A hashtable containing the specific set of variables needed by this function
        AssetNameOld : the name of a asset that was previously replaced and should be deleted
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
##################################################################################################>
function Remove-Certificate
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable] $General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable] $Specific
    )

    $General | Initialize-VenDebugLog

    # Create an API session with the Avi controller
    $AviSession = $General | New-AviApiSession

    Write-VenDebugLog "Checking for old certificate '$($Specific.AssetNameOld)'"
    try {
        # Search the Avi controller for the certificate
        $url = "https://$($General.HostAddress)/api/sslkeyandcertificate?name=$($Specific.AssetNameOld)&export_key=false"
        $AviReply = Invoke-AviRestApi -Uri $url -Method Get -WebSession $AviSession
    } catch {
        "API ERROR (Extract Certificate): $(Select-ErrorMessage($_.Exception))" | Write-VenDebugLog -ThrowException
    }

    if (-not $AviReply.Count) {
        # Certificate was not found
        Write-VenDebugLog "NOT FOUND: Certificate with asset name $($Specific.AssetNameOld) - Returning control to Venafi"
    } else {
        # Found the old certificate file - Try to delete it
        Write-VenDebugLog "Found old certificate '$($Specific.AssetNameOld)' - Attempting to delete it"
        try {
            $url = $AviReply.results.url
            Invoke-AviRestApi -Uri $url -Method Delete -WebSession $AviSession | Out-Null
            Write-VenDebugLog "Old certificate '$($Specific.AssetNameOld)' deleted - Returning control to Venafi"
        } catch {
            Write-VenDebugLog "API ERROR (Delete Certificate): $(Select-ErrorMessage($_.Exception))"
        }
    }

    # Attempt to be nice and log out of the API
    $AviSession | Remove-AviApiSession

    return @{ Result='Success' }
}


<##################################################################################################
.NAME
    Discover-Certificates
.DESCRIPTION
    Used for Onboard Discovery. Returns a list of applications with certificates which are added under
	corresponding device.
.PARAMETER General
    A hashtable containing the general set of variables needed by all or most functions (see Prepare-Keystore)
.NOTES
    Returns...
        Result : 'Success' or 'NotUsed' to indicate the non-error completion state
		Applications : An array of hashtables with discovered application data
##################################################################################################>
function Discover-Certificates
{
    # This line tells VS Code to not flag this function's name as a "problem"
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseApprovedVerbs', '', Justification='Forced by Venafi', Scope='function')]
    
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable] $General
    )

    $General | Initialize-VenDebugLog

    # Create an API session with the Avi controller
    $AviSession = $General | New-AviApiSession

    $AllVirtualServices = Get-AviVirtualServices -WebSession $AviSession

    $ref_content_map = @{}
    $ApplicationList = @()
    $sitesTotal = $sitesSSL = $sitesClear = 0
    foreach ($vs in $AllVirtualServices) {
        $sitesTotal++
        if ($vs.ssl_key_and_certificate_refs) {
            $sitesSSL++
            $ThisApp = @{}

            # Lookup the certificate filename so that it can be stored - otherwise validation won't work!
            $CertificateFileName = Get-Cert-Name-By-Ref $General $vs.ssl_key_and_certificate_refs[0] $ref_content_map $AviSession

            # Use Virtual Service name and Tenant name for Application name to prevent collisions
            $TenantName = Get-Tenant-Name-By-Ref $General $vs.tenant_ref $ref_content_map $AviSession

            $vsIP = Get-IPv4-VIP $General $vs $AviSession
            $vsPort = Get-SSL-Service-Port $vs

            # Build the application structure from collected results
            $ThisApp["Name"] = "$($vs.name) ($($TenantName))"
            $ThisApp["ApplicationClass"] = "Adaptable App"
            $ThisApp["PEM"] = Get-Certificate-By-Ref $General $vs.ssl_key_and_certificate_refs[0] $ref_content_map $AviSession
            $ThisApp["ValidationAddress"] = $vsIP
            $ThisApp["ValidationPort"] = $vsPort
            $ThisApp["Attributes"] = @{
                "Text Field 1"= $vs.name;
                "Text Field 2"= $TenantName;
                "Certificate Name"= $CertificateFileName
            }
            $ApplicationList += $ThisApp

            Write-VenDebugLog "Discovered: [$($vs.name)] on tenant [$($TenantName)] at $($vsIP):$($vsPort)"
        } else {
            $sitesClear++
            Write-VenDebugLog "Ignored: [$($vs.name)] is unencrypted"
		}
    }

    # Attempt to be nice and log out of the API
    $AviSession | Remove-AviApiSession

    Write-VenDebugLog "$($sitesTotal) virtual servers ($($sitesSSL) discovered, $($sitesClear) ignored) - Returning control to Venafi"
    return @{
        Result       = 'Success'
        Applications = $ApplicationList
    }
}

<########## THE FUNCTIONS AND CODE BELOW THIS LINE ARE NOT CALLED DIRECTLY BY VENAFI ##########>

# replace the original Write-AviLog function with an improved function set that will
# not mix up logs (especially for discoveries) and provide more useful file names

# Take a message, prepend a timestamp, output it to a debug log ... if DEBUG_FILE is set
# Otherwise do nothing and return nothing
function Write-VenDebugLog
{
    Param(
        [Parameter(Position=0, ValueFromPipeline, Mandatory)]
        [string] $LogMessage,

        [Parameter()]
        [switch] $ThrowException,

        [Parameter()]
        [switch] $NoFunctionTag
    )

    filter Add-TS {"$(Get-Date -Format o): $_"}

    # only write the log message to a file if the logfile is set...
    if ($Script:venDebugFile) {
        if ($NoFunctionTag.IsPresent) {
            $taggedLog = $LogMessage
        } else {
            $taggedLog = "[$((Get-PSCallStack)[1].Command)] $($LogMessage)"
        }

        # write the message to the debug file
        Write-Output "$($taggedLog)" | Add-TS | Add-Content -Path $Script:venDebugFile
    }

    # throw the message as an exception, if requested
    if ($ThrowException.IsPresent) {
        throw $LogMessage
    }
}

# Adding support for policy-level debug flag instead of forcing every app to be flagged

function Initialize-VenDebugLog
{
    Param(
        [Parameter(Position=0, Mandatory, ValueFromPipeline)]
        [System.Collections.Hashtable] $General
    )

    $Caller = (Get-PSCallStack)[1].Command
    if ($Script:venDebugFile) {
        Write-VenDebugLog "Called by $($Caller)"
        Write-VenDebugLog 'WARNING: Initialize-VenDebugLog() called more than once!'
        return
    }

    if (-not $DEBUG_FILE) {
        # do nothing and return immediately if debug isn't on
        if ($General.VarBool1 -eq $false) { return }

        # pull Venafi base directory from registry for global debug flag
        $logPath = "$((Get-ItemProperty HKLM:\Software\Venafi\Platform).'Base Path')Logs"
    } else {
        # use the path but discard the filename from the DEBUG_FILE variable
        $logPath = "$(Split-Path -Path $DEBUG_FILE)"
    }

    $Script:venDebugFile = "$($logPath)\$($Script:AdaptableAppDrv.Replace(' ',''))"
    if ($General.HostAddress -ne '') {
        $Script:venDebugFile += "-$($General.HostAddress)"
    }
    if ($Caller -eq 'Discover-Certificates') {
        $Script:venDebugFile += '-Discovery'
    }
    $Script:venDebugFile += ".log"
    
    Write-Output '' | Add-Content -Path $Script:venDebugFile

    Write-VenDebugLog -NoFunctionTag -LogMessage "$($Script:AdaptableAppDrv) v$($Script:AdaptableAppVer): Venafi called $($Caller)"
    Write-VenDebugLog -NoFunctionTag -LogMessage "PowerShell Environment: $($PSVersionTable.PSEdition) Edition, Version $($PSVersionTable.PSVersion.Major)"

    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"
}

function Invoke-AviRestApi
{
	Param(
		[System.Uri] $Uri,
		[Microsoft.PowerShell.Commands.WebRequestMethod] $Method,
		[System.Object] $Body,
		[int] $TimeoutSec = 15,
		[System.Collections.IDictionary] $Headers,
		[Microsoft.PowerShell.Commands.WebRequestSession] $WebSession,
        [switch]$NoRetry
	)

    Write-VenDebugLog "$((Get-PSCallStack)[1].Command)/$($Method): $($Uri)"

    $Referer = $WebSession.Headers['Referer']
    if (-not $Uri.IsAbsoluteUri) {
        # Convert a relative path supplied by the API back into a full Uri
        $Uri = ([System.Uri] ("https://$($Referer)$($Uri.OriginalString)"))
    }

    $ApiRequest = @{
        'Uri'         = $Uri
        'Method'      = $Method
        'TimeoutSec'  = $TimeoutSec
        'WebSession'  = $WebSession
    }
    if ($Headers) { $ApiRequest.Headers = $Headers }
    if ($Body)    { $ApiRequest.Body    = $Body }

	try {
        $AviReply = Invoke-RestMethod @ApiRequest -ContentType 'application/json'
        if ($WebSession.Headers['X-CSRFToken'] -ne $WebSession.Cookies.GetCookies($Referer)['csrftoken'].Value) {
            # Avi has updated the CSRF Token so we must update our headers or risk getting a 401 Unauthorized refusal
            Write-VenDebugLog "CSRF Token has been updated - Updating X-CSRFToken header"
            $WebSession.Headers['X-CSRFToken']  =  $WebSession.Cookies.GetCookies($Referer)['csrftoken'].Value
        }
	} catch [System.Net.WebException] {
        Write-VenDebugLog "REST call failed to $($Uri.AbsoluteUri)"
		if ($_.Exception.Response) {
            Write-VenDebugLog "|| Response Status Code: $($_.Exception.Response.StatusCode)"
		}
        Write-VenDebugLog "|| $(Select-ErrorMessage $_.Exception)"
        if (($_.Exception.Response.StatusCode -eq 401) -and (-not $NoRetry)) {
            # Attempt to reauthenticate and retry the API call once... just once.
            $WebSession            = $WebSession | New-AviApiSession
            $ApiRequest.WebSession = $WebSession
            $AviReply              = Invoke-AviRestApi @ApiRequest -NoRetry
        }
        if (-not $AviReply) {
		    throw $_
        }
	}

    $AviReply
}

function New-AviApiSession
{
    [CmdletBinding(DefaultParameterSetName='ApiLogin')]
    Param(
        [Parameter(Mandatory, ParameterSetName='ApiLogin', ValueFromPipeline)]
        [System.Collections.Hashtable] $General,

        [Parameter(Mandatory, ParameterSetName='RefreshApi', ValueFromPipeline)]
        [Microsoft.PowerShell.Commands.WebRequestSession] $Session
    )

    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"

    if ($General) {
        # Extract variables required for session from General hashtable
        $AviHost   = $General.HostAddress
        $UserName  = $General.UserName
        $UserPass  = $General.UserPass
        if ($General.VarText2) {
            $AviTenant = $General.VarText2
        } else {
            $AviTenant = '*'
        }
    } elseif ($Session) {
        # Extract variables required for session from existing/old session
        $AviHost   = (([System.Uri]($Session.Headers['Referer'])).Host)
        $UserName  = $Session.Credentials.UserName
        $UserPass  = $Session.Credentials.GetNetworkCredential().Password
        $AviTenant = $Session.Headers['X-Avi-Tenant']
    }

    $RequestBody = @{ 'username'=$UserName; 'password'=$UserPass } | ConvertTo-Json
    $ApiLogin = @{
        'Uri'             = [System.Uri]"https://$($AviHost)/login"
        'Method'          = 'Post'
        'TimeoutSec'      = 30
        'ContentType'     = 'application/json'
        'Body'            = $RequestBody
        'SessionVariable' = 'NewWebSession'
    }

    try {
        Write-VenDebugLog "Logging into AVI controller [$($AviHost)] as [$($UserName)]"
        $AviReply = Invoke-RestMethod @ApiLogin -ErrorVariable InvokeError
        if (-not $AviReply.user.username) {
            "Login Failure: $($AviReply|ConvertTo-Json -Depth 5)" | Write-VenDebugLog -ThrowException
        }
    } catch [System.Net.WebException] {
        Write-VenDebugLog "REST call failed to $($ApiLogin.Uri.AbsoluteUri)"
		if ($_.Exception.Response) {
            Write-VenDebugLog "Response Status Code: $($_.Exception.Response.StatusCode.value__.ToString())"
		}
        Write-VenDebugLog "$(Select-ErrorMessage $_.Exception)"
		throw $_
    } catch {
        # Generic catch block for any other terminating errors
        Write-VenDebugLog "An unexpected error occurred: $($_.Exception.Message)"
    }

    $AviVersion = $AviReply.version.Version
    Write-VenDebugLog "Login successful: AVI controller is running version [$($AviVersion)]"
	$NewWebSession.Headers.Add('X-Avi-Version', $AviVersion)
	$NewWebSession.Headers.Add('X-Avi-Tenant',  $AviTenant)
	$NewWebSession.Headers.Add('Content-Type',  'application/json')
	$NewWebSession.Headers.Add('Referer',       "https://$($AviHost)")
	$NewWebSession.Headers.Add('X-CSRFToken',   $($NewWebSession.Cookies.GetCookies("https://$($AviHost)")['csrftoken'].Value))

    $SecureStringPassword      = ConvertTo-SecureString -String $UserPass -AsPlainText -Force
    $NewWebSession.Credentials = New-Object System.Management.Automation.PSCredential($UserName, $SecureStringPassword)

    $NewWebSession
}

function Remove-AviApiSession
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [Microsoft.PowerShell.Commands.WebRequestSession] $WebSession
    )

    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"

    $AviHost         = (([System.Uri]($WebSession.Headers['Referer'])).Host)
    $UserName        = $WebSession.Credentials.UserName
    [System.Uri]$Uri = "https://$($AviHost)/logout"
    Write-VenDebugLog "Logging [$($UserName)] out of AVI controller [$($AviHost)]"

    # Try to logout but do not throw terminating errors for a failed logout
    # At this point we're done talking to the Avi so the logout is cleanup, but not mandatory
    try {
        Invoke-AviRestApi -Uri $Uri -Method Post -WebSession $WebSession | Out-Null
    } catch [System.Net.WebException] {
        Write-VenDebugLog "REST call failed to $($Uri.AbsoluteUri)"
		if ($_.Exception.Response) {
            Write-VenDebugLog "Response Status Code: $($_.Exception.Response.StatusCode.value__.ToString())"
		}
        Write-VenDebugLog "$(Select-ErrorMessage $_.Exception)"
    } catch {
        # Generic catch block for any other terminating errors
        Write-VenDebugLog "An unexpected error occurred: $($_.Exception.Message)"
    }
}

function Get-AviVirtualServices
{
	Param(
        [Parameter(Mandatory)]
		[Microsoft.PowerShell.Commands.WebRequestSession] $WebSession,

        [int] $TimeoutSec = 300
	)

    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"

    $ApiCall = 0
    $VirtualServicesList = @()
    $uri = "$($WebSession.Headers['Referer'])/api/virtualservice"
    while ($uri) {
        # Keep retrieving virtual services until we have them all
        $ApiCall++
        $AviReply = Invoke-AviRestApi -Uri $uri -Method Get -TimeoutSec $TimeoutSec -WebSession $WebSession
        $VirtualServicesList += $AviReply.results
        if (($AviReply.next) -and ($ApiCall -eq 1)) {
            $s = ''
            if ($AviReply.results.Count -ne 1) { $s = 's'}
            Write-VenDebugLog "API call #1 returned $($AviReply.results.Count) virtual server$($s)"
        } elseif (($AviReply.next) -or ($ApiCall -gt 1)) {
            $s = ''
            if ($AviReply.results.Count -ne 1) { $s = 's'}
            Write-VenDebugLog "API call #$($ApiCall) returned $($AviReply.results.Count) more virtual server$($s) (Total So Far: $($VirtualServicesList.Count))"
        }
        $uri = $AviReply.next
    }

    $Summary = "DONE: Retrieved [$($VirtualServicesList.Count)] virtual servers"
    if ($ApiCall -gt 1) { $Summary += " via [$($ApiCall)] API calls" }
    Write-VenDebugLog $Summary

    $VirtualServicesList
}

function Get-Tenant-Name-By-Ref([System.Collections.Hashtable] $General, [string] $tref, [System.Collections.Hashtable] $ref_content_map, [Microsoft.PowerShell.Commands.WebRequestSession] $session)
{
    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"

    if (-not $ref_content_map.$tref) {
        $AviReply = Invoke-AviRestApi -Uri $tref -Method Get -WebSession $session
		$ref_content_map.$tref = $AviReply.name
        Write-VenDebugLog "Added tenant name to cache: [$($ref_content_map.$tref)]"
    } else {
        Write-VenDebugLog "Tenant name retrieved from cache: [$($ref_content_map.$tref)]"
    }

    $ref_content_map.$tref
}

function Get-Certificate-By-Ref([System.Collections.Hashtable] $General, [string] $ssl_ref, [System.Collections.Hashtable] $ref_content_map, [Microsoft.PowerShell.Commands.WebRequestSession] $session)
{
    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"

    if (-not $ref_content_map.$ssl_ref) {
        $AviReply = Invoke-AviRestApi -Uri $ssl_ref -Method Get -WebSession $session
		$ref_content_map.$ssl_ref = $AviReply.certificate.certificate
        Write-VenDebugLog "Added certificate to cache: [$($ssl_ref)]"
        $ssl_name_ref = "$($ssl_ref)/name"
		$ref_content_map.$ssl_name_ref = $AviReply.name
        Write-VenDebugLog "Added filename to cache: [$($ref_content_map.$ssl_name_ref)]"
    } else {
        Write-VenDebugLog "Certificate retrieved from cache: [$($ssl_ref)]"
    }

    $ref_content_map.$ssl_ref
}

# modified - add a function to perform certificate filename lookup
function Get-Cert-Name-By-Ref([System.Collections.Hashtable] $General, [string] $ssl_ref, [System.Collections.Hashtable] $ref_content_map, [Microsoft.PowerShell.Commands.WebRequestSession] $session)
{
    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"

    $ssl_name_ref = "$($ssl_ref)/name"
    if (-not $ref_content_map.$ssl_name_ref) {
        $AviReply = Invoke-AviRestApi -Uri $ssl_ref -Method Get -WebSession $session
		$ref_content_map.$ssl_ref = $AviReply.certificate.certificate
        Write-VenDebugLog "Added certificate to cache: [$($ssl_ref)]"
		$ref_content_map.$ssl_name_ref = $AviReply.name
        Write-VenDebugLog "Added filename to cache: [$($ref_content_map.$ssl_name_ref)]"
    } else {
        Write-VenDebugLog "Filename retrieved from cache: [$($ref_content_map.$ssl_name_ref)]"
    }

    $ref_content_map.$ssl_name_ref
}

function Get-IPv4-VIP([System.Collections.Hashtable] $General, $vs, [Microsoft.PowerShell.Commands.WebRequestSession] $session)
{
    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"

    $AviReply = Invoke-AviRestApi -Uri $vs.vsvip_ref -Method Get -WebSession $session

    foreach ($vip_def in $AviReply.vip) {
        if ($vip_def.floating_ip) {
            if ($vip_def.floating_ip.type -eq "V4") {
                Write-VenDebugLog "Floating IP for $($vs.name) is $($vip_def.floating_ip.addr)"
                return $vip_def.floating_ip.addr
            }
        } elseif ($vip_def.ip_address.type -eq "V4") {
            Write-VenDebugLog "No floating IP for $($vs.name). Private IP is $($vip_def.ip_address.addr)"
            return $vip_def.ip_address.addr
        }
    }
    Write-VenDebugLog "Returning... nothing?!"
}

function Get-SSL-Service-Port($vs_json)
{
    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"

    foreach($port in $vs_json.services) {
        if ($port.enable_ssl -eq $true) {
            [string] $vsPort = $port.port
            Write-VenDebugLog "Service port for $($vs_json.name) is $($vsPort)"
			return $vsPort
        }
    }
    Write-VenDebugLog "Returning... nothing?!"
}

function Get-CACertName
{
    Param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $CACert
    )

    # name should not have any non-alphanumeric characters including whitespace
    $alphanumeric = '[^a-zA-Z0-9]'
    
    # use GetNameInfo to be consistent with Microsoft's naming
    $name = $CACert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
    $name = $name -replace $alphanumeric
    
    # append the last 4 characters of the serial number in case there has been reissuance of the CA certificate
    return $name + "_" + $CACert.SerialNumber.Substring($CACert.SerialNumber.Length-4)
}


function Select-ErrorMessage
{
    Param(
        [Parameter(Position=0, Mandatory, ValueFromPipeline)]
        [Exception] $ex
    )

    try {
        $result = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($result)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $rawResponse = $reader.ReadToEnd()
        $json = $rawResponse | ConvertFrom-Json
    } catch {
        # The response doesn't contain an error message or isn't JSON
        # Ignore error and continue processing
    }

    # If we decoded an error string in the JSON return that
    if ($json.error) {
        return $json.error
    } elseif ($json.detail) {
        return $json.detail
    } else {
        # Write the raw results to the log file for further debugging
        Write-VenDebugLog "Raw Error Response: $($rawResponse)"
    }

    # Otherwise return the exception error message
    return $ex.Message
}

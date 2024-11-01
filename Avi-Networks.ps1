<#
//----------------------------------------------------------------------- 
// Avi Networks.ps1
//
// Copyright (c) 2017 Venafi, Inc.  All rights reserved. 
//
// This sample script and its contents are provided by Venafi to customers 
// and authorized technology partners for the purposes of integrating with
// services and platforms that are not owned or supported by Venafi.  Any 
// sharing of this script or its contents without consent from Venafi is 
// prohibited.
//
// This sample is provided "as is" without warranty of any kind.
//----------------------------------------------------------------------- 

Modifications to Avi Networks driver coding:
- changed naming convention for discovered certificates to "vs_name (tenant_name)" to better avoid collisions
- extract and save certificate name for proper validation after discovery ... bad bug!
- fix get-allvs to actually return more than 25 virtual services by supporting pagination ... another bad bug!
- logging has been extensively overhauled to utilize better separation of logs, more useful log filenames,
-- and an end to multiple discovery processes writing into the same logs which greatly reduces their usefulness.

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

$Script:AdaptableAppVer = "202404301045"
$Script:AdaptableAppDrv = "Avi-Networks"

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
        [System.Collections.Hashtable]$General
    )

    return @{ Result="NotUsed"; }
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
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )
   
    return @{ Result="NotUsed"; }
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
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    Initialize-VenDebugLog -General $General

	if ( -not $($Specific.SubjectDn.CN) ) {
        throw "Common Name is required by Avi Vantage for remotely generated CSRs."
    }
    else {
        $subject = @{ "common_name"=$($Specific.SubjectDn.CN) }
    }

    if ( $Specific.SubjectDn.OU ) {
        # only one OU is currently supported so we always use the first if there are many
        $subject.Add( "organization_unit", $Specific.SubjectDn.OU[0] )
    }

    if ( $Specific.SubjectDn.O ) {
        $subject.Add( "organization", $Specific.SubjectDn.O )
    }

    if ( $Specific.SubjectDn.L ) {
        $subject.Add( "locality", $Specific.SubjectDn.L )
    }

    if ( $Specific.SubjectDn.ST ) {
        $subject.Add( "state", $Specific.SubjectDn.ST )
    }

    if ( $Specific.SubjectDn.C ) {
        $subject.Add( "country", $Specific.SubjectDn.C )
    }

    $sans_dns = @() + $($Specific.SubjAltNames.DNS | Where-Object {$_})  # an array of DNS Subject Alternative Names, possibly empty

    try {
        $session = Get-AviSession $General.HostAddress $General.UserName $General.UserPass

        $headers = @{
			"content-type"="application/json";
			"referer"="https://$($General.HostAddress)";
			"X-Avi-Tenant"=$General.VarText2;
			"x-csrftoken"=$($session.Cookies.GetCookies("https://$($General.HostAddress)")["csrftoken"].Value)
        }

        [string] $url = "https://$($General.HostAddress)/api/sslkeyandcertificate"

        $body = @{
        	"name"=$General.AssetName;
	        "certificate"=@{
		        "self_signed"=$false;
		        "subject"=$subject;
                "subject_alt_names"=$sans_dns;
	        };
            "type"="SSL_CERTIFICATE_TYPE_VIRTUALSERVICE";
            "key_params"=@{
                "algorithm"="SSL_KEY_ALGORITHM_RSA";
                "rsa_params"=@{
                    "key_size"=$("SSL_KEY_" + $Specific.KeySize + "_BITS")
                }
            }
        } | ConvertTo-Json

        Write-VenDebugLog "Creating new remotely generated CSR for '$($General.AssetName)'"
        $resp_obj = Invoke-AviRestMethod -Uri $url -Method Post -Headers $headers -Body $body -ContentType "application/json" -WebSession $session
		$csr_uuid = $resp_obj.response.uuid
        Write-VenDebugLog "New CSR created (CSR UUID: $($csr_uuid))"
		[string] $url = "https://$($General.HostAddress)/api/sslkeyandcertificate/$csr_uuid"
		$resp_obj = Invoke-AviRestMethod -Uri $url -Method Get -Headers $headers -ContentType "application/json" -WebSession $session
        $csr = $resp_obj.response.certificate.certificate_signing_request
        Write-VenDebugLog 'Returning control to Venafi'

        return @{ Result="Success"; Pkcs10=$csr }
    }
    catch {
        throw Select-ErrorMessage($_.Exception)
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
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    Initialize-VenDebugLog -General $General

    try
    {
        $session = Get-AviSession $General.HostAddress $General.UserName $General.UserPass
        $headers = @{
			"content-type"="application/json";
			"referer"="https://$($General.HostAddress)";
			"X-Avi-Tenant"=$General.VarText2;
			"x-csrftoken"=$($session.Cookies.GetCookies("https://$($General.HostAddress)")["csrftoken"].Value)
        }
        if ( $Specific.ChainPkcs7 )
        {
            $chain = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
            $chain.Import( $Specific.ChainPkcs7 )
            foreach ( $cert in $chain )
            {
                $is_installed = $false
                $cacert_name = $cacert_basename = Get-CACertName $cert
				for ( $i=0; $i -lt 10; $i++ ) 
                {
                    Write-VenDebugLog "Preparing to upload CA certificate: [$($cacert_name)]"
					# check to see if a certificate already exists by the name
                    $url = "https://$($General.HostAddress)/api/sslkeyandcertificate?name=$cacert_name&export_key=false"
					$resp_obj = Invoke-AviRestMethod -Uri $url -Method Get -Headers $headers -ContentType "application/json" -WebSession $session
                    $response = $resp_obj.response
					if ( $response.Count -ne 0 ) # name collision, is it the same cert?
                    {
						$pem = $response.results.certificate.certificate
                        $pem = $pem.Replace("-----BEGIN CERTIFICATE-----","").Replace("-----END CERTIFICATE-----","")
                        $cert_existing = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                        $cert_existing.Import([Convert]::FromBase64String($pem))
                        if ( $cert_existing.Equals($cert) ) # this certificate is already installed
                        {
                            Write-VenDebugLog "CA certificate '$($cacert_name)' has already been installed."
                            $is_installed = $true
							break
                        }
                        else # append an integer and test that name for uniqueness
                        {
                            Write-VenDebugLog "CA certificate '$($cacert_name)' exists, but does not match!"
                            $cacert_name = $cacert_basename + "_" + $idx
                        }
                    }
                    else # install the CA certificate
                    {
                        $pem = [Convert]::ToBase64String($cert.RawData, [System.Base64FormattingOptions]::InsertLineBreaks)
                        $url = "https://$($General.HostAddress)/api/sslkeyandcertificate"
                        $body = @{
                            "certificate"=@{
                                "certificate"="-----BEGIN CERTIFICATE-----`n$pem`n-----END CERTIFICATE-----"
                            };
                            "name"=$cacert_name;
                            "type"="SSL_CERTIFICATE_TYPE_CA"
                        } | ConvertTo-Json
                        Invoke-AviRestMethod -Uri $url -Method Post -Headers $headers -Body $body -ContentType "application/json" -WebSession $session
                        Write-VenDebugLog "CA certificate '$($cacert_name)' has been uploaded."
                        $is_installed = $true
                        break
                    }
                }
                if ( -not $is_installed )
                {
                    Write-VenDebugLog "Conflict resolution failed for '$($cacert_basename)'"
                    throw "Automatic name conflict resolution threshold was exceeded for '" + $cacert_basename + "'"
                }
            }
        }
        Write-VenDebugLog "CA chain installed - Returning control to Venafi"
        return @{ Result="Success"; }
    }
    catch
    {
        throw Select-ErrorMessage($_.Exception)
    }
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
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    return @{ Result="NotUsed" }
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
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    Initialize-VenDebugLog -General $General

    try {
        $session = Get-AviSession $General.HostAddress $General.UserName $General.UserPass
        $cert = $Specific.CertPem
        $key = $Specific.PrivKeyPem
        $headers = @{
			"content-type"="application/json";
			"referer"="https://$($General.HostAddress)";
            "X-Avi-Tenant"=$General.VarText2;
			"x-csrftoken"=$($session.Cookies.GetCookies("https://$($General.HostAddress)")["csrftoken"].Value)
        }
        Write-VenDebugLog "Preparing to upload certificate: [$($General.AssetName)]"
        if ( $key ) # this is central generation
        {
            # check to see if a certificate already exists by the name
            $url = "https://$($General.HostAddress)/api/sslkeyandcertificate?name=$($General.AssetName)&export_key=false"
			$resp_obj = Invoke-AviRestMethod -Uri $url -Method Get -Headers $headers -ContentType "application/json" -WebSession $session
			$response = $resp_obj.response
            if ( $response.Count -ne 0 ) # name collision, is it the same cert?
            {
                $pem = $cert.Replace("-----BEGIN CERTIFICATE-----","").Replace("-----END CERTIFICATE-----","")
                $cert_installing = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                $cert_installing.Import([Convert]::FromBase64String($pem))
                $pem = $response.results.certificate.certificate
                $pem = $pem.Replace("-----BEGIN CERTIFICATE-----","").Replace("-----END CERTIFICATE-----","")
                $cert_existing = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                $cert_existing.Import([Convert]::FromBase64String($pem))
                if ( $cert_existing.Equals($cert_installing) ) # this certificate is already installed
                {
                    Write-VenDebugLog "Certificate is already installed - Returning control to Venafi"
                    return @{ Result="AlreadyInstalled"; }
                }
                else {
                    Write-VenDebugLog "ERROR: A different certificate is installed as '$($General.AssetName)' - Returning control to Venafi"
                    throw "A different certificate already exists with the name '" + $General.AssetName + "'"
                }
            }
            $url = "https://$($General.HostAddress)/api/sslkeyandcertificate"            
            $body = @{
	            "certificate"=@{
		            "certificate"=$cert;
	            };
                "key"=$key;
	            "name"=$General.AssetName;
                "type"="SSL_CERTIFICATE_TYPE_VIRTUALSERVICE"
            } | ConvertTo-Json
            # Note: this call requires the x-csrftoken HTTP header to avoid (401) Unauthorized
            Invoke-AviRestMethod -Uri $url -Method Post -Headers $headers -Body $body -ContentType "application/json" -WebSession $session
            Write-VenDebugLog "Certificate has been uploaded as '$($General.AssetName)' - Returning control to Venafi"
            return @{ Result="Success"; }
        }
        else # this is remote generation
        {
            # lookup the CSR
            Write-VenDebugLog "Searching for remotely generated CSR for '$($General.AssetName)'"
            $url = "https://$($General.HostAddress)/api/sslkeyandcertificate?name=$($General.AssetName)&export_key=false"
			$resp_obj = Invoke-AviRestMethod -Uri $url -Method Get -Headers $headers -ContentType "application/json" -WebSession $session
			$response = $resp_obj.response
            if ( $response.Count -ne 0 ) # found it
            {
                if ( -not $response.results.certificate.certificate ) {
                    # install the certificate
                    $url = $response.results.url
					$response.results.certificate | Add-Member -MemberType NoteProperty -Name 'certificate' -Value $cert
                    $body = $response.results | ConvertTo-Json

                    # Note: this call requires the x-csrftoken HTTP header to avoid (401) Unauthorized
                    Invoke-AviRestMethod -Uri $url -Method Put -Headers $headers -Body $body -ContentType "application/json" -WebSession $session
                    Write-VenDebugLog "Certificate has been uploaded as '$($General.AssetName)' - Returning control to Venafi"
                    return @{ Result="Success"; }
                }
                else {
                    Write-VenDebugLog "ERROR: A different certificate is installed as '$($General.AssetName)' - Returning control to Venafi"
                    throw "A certificate is unexpectedly already installed on '" + $General.AssetName + "'"
                }
            }
            else {
                Write-VenDebugLog "ERROR: Remotely generated CSR not found for '$($General.AssetName)'"
                throw "Remotely generated CSR was not found with name '" + $General.AssetName + "'"
            }
        }
    }
    catch {
        throw Select-ErrorMessage($_.Exception)
    }
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
        [System.Collections.Hashtable]$General
    )

    Initialize-VenDebugLog -General $General

    $session = Get-AviSession $General.HostAddress $General.UserName $General.UserPass
	$tenant_name = $General.VarText2
    $headers = @{
		"content-type"="application/json";
		"referer"="https://$($General.HostAddress)";
		"X-Avi-Tenant"=$tenant_name;
		"x-csrftoken"=$($session.Cookies.GetCookies("https://$($General.HostAddress)")["csrftoken"].Value)
    }
	$vs_name = $General.VarText1
    # Get Virtual Service UUID
    $url = "https://$($General.HostAddress)/api/virtualservice?name={0}" -f $vs_name
    Write-VenDebugLog "Retrieving configuration for virtual service '$($vs_name)'"
	$resp_obj = Invoke-AviRestMethod -Uri $url -Method Get -Headers $headers -WebSession $session
	$resp_vs = $resp_obj.response
	if ($resp_vs.count -eq 0) {
        Write-VenDebugLog "Could not find virtual service '$($vs_name)'"
		throw "Could not find virtual service '$($vs_name)'"
	}
	$vs_uuid = $resp_vs.results[0].uuid
   
    # Get Certificate UUID
	$cert_avi_name = $General.AssetName
    $url = "https://$($General.HostAddress)/api/sslkeyandcertificate?name={0}" -f $cert_avi_name
	$resp_obj = Invoke-AviRestMethod -Uri $url -Method Get -Headers $headers -WebSession $session
	$resp = $resp_obj.response
	if($resp.count -eq 0) {
        Write-VenDebugLog "Certificate '$($cert_avi_name)' not found!"
		throw "Certificate '$($cert_avi_name)' not found!"
	}
    $cert_uuid = $resp.results[0].url
 
    # Associate certificate with virtual service instance
    $url = "https://$($General.HostAddress)/api/virtualservice/" + $vs_uuid
   
    $body = $resp_vs.results[0]
    $body.ssl_key_and_certificate_refs=@( $cert_uuid ) 
    $body = $body | ConvertTo-Json -depth 100

    # Note: this call requires the x-csrftoken HTTP header to avoid (401) Unauthorized
    Write-VenDebugLog "Binding certificate '$($cert_avi_name)' to virtual service '$($vs_name)'"
	Invoke-AviRestMethod -Uri $url -Method Put -Headers $headers -Body $body -ContentType "application/json" -WebSession $session
    Write-VenDebugLog "Virtual service has been updated - Returning control to Venafi"
    return @{ Result="Success"; }
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
        [System.Collections.Hashtable]$General
    )
    
    return @{ Result="NotUsed"; }
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
        [System.Collections.Hashtable]$General
    )

    Initialize-VenDebugLog -General $General

    try {
		$session = Get-AviSession $General.HostAddress $General.UserName $General.UserPass
		$headers = @{
			"content-type"="application/json";
			"referer"="https://$($General.HostAddress)";
			"X-Avi-Tenant"=$General.VarText2;
			"x-csrftoken"=$($session.Cookies.GetCookies("https://$($General.HostAddress)")["csrftoken"].Value)
		}
        $url = "https://$($General.HostAddress)/api/sslkeyandcertificate?name=$($General.AssetName)&export_key=false"
        $resp_obj = Invoke-AviRestMethod -Uri $url -Method Get -Headers $headers -ContentType "application/json" -WebSession $session
		$response = $resp_obj.response
        if ( $response.Count -ne 0 ) # certificate exists
        {
			$pem = $response.results.certificate.certificate
            $idx = $response.results.certificate.fingerprint.IndexOf('=')
            $thumbprint = $response.results.certificate.fingerprint.Remove(0,$idx+1).Replace(":","").ToLower().Trim()
            $serial = "{0:x}" -f [bigint]$($response.results.certificate.serial_number)
            Write-VenDebugLog "Certificate Asset Name:    $($General.AssetName)"
            Write-VenDebugLog "Certificate Serial Number: $($serial)"
            Write-VenDebugLog "Certificate Thumbprint:    $($thumbprint)"
#            Write-VenDebugLog "Certificate Valid Until:   $()"
            Write-VenDebugLog "Certificate extracted successfully - Returning control to Venafi"
            return @{Result="Success"; CertPem="$pem"; Serial="$serial"; Thumprint="$thumbprint"}
        }
        else {
            Write-VenDebugLog "NOT FOUND: Certificate with asset name $($General.AssetName) - Returning control to Venafi"
            throw "No certificate named '" + $General.AssetName + "' was found."
        }
    }
    catch {
        Write-VenDebugLog "API error: $($_.Exception)"
        Write-VenDebugLog "FAILED to extract certificate - Returning control to Venafi"
        throw Select-ErrorMessage($_.Exception)
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
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    Initialize-VenDebugLog -General $General

    try {
		$session = Get-AviSession $General.HostAddress $General.UserName $General.UserPass
		$tenant_name = $General.VarText2
		$headers = @{
			"content-type"="application/json";
			"referer"="https://$($General.HostAddress)";
			"X-Avi-Tenant"=$tenant_name;
			"x-csrftoken"=$($session.Cookies.GetCookies("https://$($General.HostAddress)")["csrftoken"].Value)
		}
        $url = "https://$($General.HostAddress)/api/sslkeyandcertificate?name=$($General.AssetName)&export_key=true"
        $resp_obj = Invoke-AviRestMethod -Uri $url -Method Get -Headers $headers -ContentType "application/json" -WebSession $session
		$response = $resp_obj.response
        if ( $response.Count -ne 0 ) # certificate and private key exist
        {
            Write-VenDebugLog "Private key found for certificate '$($General.AssetName)' - Returning control to Venafi"
            $pem = $response.results.key
            return @{ Result="Success"; PrivKeyPem="$pem" }
        }
        else {
            Write-VenDebugLog "Export failed (Certificate '$($General.AssetName)' not found) - Returning control to Venafi"
            throw "No certificate named '" + $General.AssetName + "' was found to export private key."
        }
    }
    catch {
        throw Select-ErrorMessage($_.Exception)
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
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    Initialize-VenDebugLog -General $General

	$cert_avi_name = $Specific.AssetNameOld
	$session = Get-AviSession $General.HostAddress $General.UserName $General.UserPass
	$tenant_name = $General.VarText2
    $headers = @{
		"content-type"="application/json";
		"referer"="https://$($General.HostAddress)";
		"X-Avi-Tenant"=$tenant_name;
		"x-csrftoken"=$($session.Cookies.GetCookies("https://$($General.HostAddress)")["csrftoken"].Value)
    }
    $url = "https://$($General.HostAddress)/api/sslkeyandcertificate?name=$($Specific.AssetNameOld)&export_key=false"
    Write-VenDebugLog "Checking for old certificate '$($cert_avi_name)'"
	$resp_obj = Invoke-AviRestMethod -Uri $url -Method Get -Headers $headers -ContentType "application/json" -WebSession $session
	$response = $resp_obj.response
    if ( $response.Count -ne 0 ) # certificate exists so try to delete it
    {
		$url = $response.results.url
        Write-VenDebugLog "Found old certificate '$($cert_avi_name)' - Attempting to delete it"
        Invoke-AviRestMethod -Uri $url -Method Delete -Headers $headers -WebSession $session
        Write-VenDebugLog "Old certificate '$($cert_avi_name)' deleted - Returning control to Venafi"
    }
	else {
        Write-VenDebugLog "Old certificate '$($cert_avi_name)' not found"
	}
    return @{ Result="Success"; }
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
        [System.Collections.Hashtable]$General
    )

    Initialize-VenDebugLog -General $General

	$login_session = Get-AviSession $General.HostAddress $General.UserName $General.UserPass
	$all_vs = Get-AllVS $General $login_session
    $ref_content_map = @{}
    $results = @()
    $sitesTotal=$sitesSSL=$sitesClear=0
    foreach ($vs in $all_vs) {
        $sitesTotal++
        if ($vs.ssl_key_and_certificate_refs) {
            $sitesSSL++
            $temp = @{}
# modified - lookup the actual certificate filename so that it can be stored - otherwise validation won't work!
            $cert_filename = Get-Cert-Name-By-Ref $General $vs.ssl_key_and_certificate_refs[0] $ref_content_map $login_session
# modified - replace bad naming convention to prevent collisions
            $tenant_name = Get-Tenant-Name-By-Ref $General $vs.tenant_ref $ref_content_map $login_session
            $vsIP = Get-IPv4-VIP $General $vs $login_session
            $vsPort = Get-SSL-Service-Port $vs
            $temp["Name"] = "{0} ({1})" -f $vs.name, $tenant_name
            $temp["ApplicationClass"] = "Adaptable App"
            $temp["PEM"] = Get-Certificate-By-Ref $General $vs.ssl_key_and_certificate_refs[0] $ref_content_map $login_session
            $temp["ValidationAddress"] = $vsIP
            $temp["ValidationPort"] = $vsPort
            $temp["Attributes"] = @{
                "Text Field 1"= $vs.name;
                "Text Field 2"= $tenant_name;
# modified - insert required certificate filename so that validation actually works
                "Certificate Name"= $cert_filename
            }
            $results += $temp
            Write-VenDebugLog "Discovered: [$($vs.name)] on tenant [$($tenant_name)] at $($vsIP):$($vsPort)"
        }
		else{
            $sitesClear++
            Write-VenDebugLog "Ignored: [$($vs.name)] is unencrypted"
		}
    }
    Write-VenDebugLog "$($sitesTotal) virtual servers ($($sitesSSL) discovered, $($sitesClear) ignored) - Returning control to Venafi"
    return @{
        Result="Success";
        Applications = $results
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
        [Parameter(Position=0, Mandatory)][string]$LogMessage,
        [switch]$NoFunctionTag
    )

    filter Add-TS {"$(Get-Date -Format o): $_"}

    # if the logfile isn't initialized then do nothing and return immediately
    if ($null -eq $Script:venDebugFile) { return }

    if ($NoFunctionTag.IsPresent) {
        $taggedLog = $LogMessage
    }
    else {
        $taggedLog = "[$((Get-PSCallStack)[1].Command)] $($LogMessage)"
    }

    # write the message to the debug file
    Write-Output "$($taggedLog)" | Add-TS | Add-Content -Path $Script:venDebugFile
}

# Adding support for policy-level debug flag instead of forcing every app to be flagged

function Initialize-VenDebugLog
{
    Param(
        [Parameter(Position=0, Mandatory)][System.Collections.Hashtable]$General
    )

    if ($null -ne $Script:venDebugFile) {
        Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"
        Write-VenDebugLog 'WARNING: Initialize-VenDebugLog() called more than once!'
        return
    }

    if ($null -eq $DEBUG_FILE) {
        # do nothing and return immediately if debug isn't on
        if ($General.VarBool1 -eq $false) { return }
        # pull Venafi base directory from registry for global debug flag
        $logPath = "$((Get-ItemProperty HKLM:\Software\Venafi\Platform).'Base Path')Logs"
    }
    else {
        # use the path but discard the filename from the DEBUG_FILE variable
        $logPath = "$(Split-Path -Path $DEBUG_FILE)"
    }

    $Script:venDebugFile = "$($logPath)\$($Script:AdaptableAppDrv.Replace(' ',''))"
    if ($General.HostAddress -ne '') {
        $Script:venDebugFile += "-$($General.HostAddress)"
    }
    $Script:venDebugFile += ".log"
    
    Write-Output '' | Add-Content -Path $Script:venDebugFile

    Write-VenDebugLog -NoFunctionTag -LogMessage "$($Script:AdaptableAppDrv) v$($Script:AdaptableAppVer): Venafi called $((Get-PSCallStack)[1].Command)"
    Write-VenDebugLog -NoFunctionTag -LogMessage "PowerShell Environment: $($PSVersionTable.PSEdition) Edition, Version $($PSVersionTable.PSVersion.Major)"

    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"

#    Write-VenDebugLog 'GENERAL VARIABLES'
#    $General.keys | %{ Add-Content -Path $Script:venDebugFile "$_ : $($General.$_)" }
}

function Invoke-AviRestMethod
{
	Param(
		[Uri] $Uri,
		[Microsoft.PowerShell.Commands.WebRequestMethod] $Method,
		[System.Object] $Body,
		[string] $ContentType,
		[string] $SessionVariable,
		[int] $TimeoutSec,
		[System.Collections.IDictionary] $Headers,
		[Microsoft.PowerShell.Commands.WebRequestSession] $WebSession
	)
    Write-VenDebugLog "$((Get-PSCallStack)[1].Command)/$($Method): $($Uri)"
	try {
		if($WebSession){
			$response = Invoke-RestMethod -Uri $Uri -Method $Method -Headers $Headers -Body $Body -ContentType $ContentType -WebSession $WebSession -TimeoutSec $TimeoutSec
			return @{
				response=$response;
				session=$WebSession;
			}
		}
		if($SessionVariable){
			$response = Invoke-RestMethod -Uri $Uri -Method $Method -Headers $Headers -Body $Body -ContentType $ContentType -SessionVariable new_session -TimeoutSec $TimeoutSec
			return @{
				response=$response;
				session=$new_session
			}
		}
	}
	catch [System.Net.WebException] {
        Write-VenDebugLog "REST call failed to $($Uri.AbsoluteUri)"
		if ($_.Exception.Response) {
			[string] $debug_msg = "Status Code of response : {0}" -f $_.Exception.Response.StatusCode.value__.ToString()
            Write-VenDebugLog $debug_msg
			$debug_msg = Select-ErrorMessage $_.Exception
            Write-VenDebugLog $debug_msg
		}
		else {
			$debug_msg = Select-ErrorMessage $_.Exception
            Write-VenDebugLog $debug_msg
		}
		throw $_
	}
}

function Get-AviSession( [string] $addr, [string] $user, [string] $pass )
{
    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"

    [string] $url = "https://{0}/login" -f $addr
    $body = @{
        "username"=$user;
        "password"=$pass
    } | ConvertTo-Json
    Write-VenDebugLog "Login to [$($addr)] as [$($user)]"
	$resp_obj = Invoke-AviRestMethod -Uri $url -Method Post -Body $body -ContentType "application/json" -SessionVariable session -TimeoutSec 300
	$response = $resp_obj.response
	$session = $resp_obj.session
	$x_avi_version = $response.version.Version
    Write-VenDebugLog "Logged into AVI controller [$($addr)] (Version $($x_avi_version)) as [$($user)]"
	$session.Headers.Add([string] "X-Avi-Version", $x_avi_version)
	$session.Headers.Add([string] "content-type", [string] "application/json")
	$session.Headers.Add([string] "referer", [string] "https://$addr")
	$session.Headers.Add([string] "x-csrftoken", $($session.Cookies.GetCookies("https://$addr")["csrftoken"].Value))
	return $session
}

function Get-AllVs([System.Collections.Hashtable] $General, [Microsoft.PowerShell.Commands.WebRequestSession] $session)
{
    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"

    [string] $all_vs_request_url = "https://{0}/api/virtualservice" -f $General.HostAddress
    $headers = @{
        "X-Avi-Tenant"="*";
    }
	$resp_obj = Invoke-AviRestMethod -Uri $all_vs_request_url -Method Get -Headers $headers -ContentType "application/json" -WebSession $session -TimeoutSec 300
	# modified - everything below this line changed in some way...
    $vsCount = $resp_obj.response.count
    $vsList  = $resp_obj.response.results
    $apiCall = 1
    Write-VenDebugLog "API returned $(@($resp_obj.response.results).Count) virtual servers"
    while ($null -ne $resp_obj.response.next) {
        $apiCall++
        $resp_obj = Invoke-AviRestMethod -Uri ($resp_obj.response.next) -Method Get -Headers $headers -ContentType "application/json" -WebSession $session -TimeoutSec 300
        $vsList += $resp_obj.response.results
        Write-VenDebugLog "API returned $(@($resp_obj.response.results).Count) more virtual servers"
    }
    Write-VenDebugLog "Retrieved [$($vsCount)] virtual servers via [$($apiCall)] API calls to [$($General.HostAddress)]"
	return $vsList
}

function Get-Tenant-Name-By-Ref([System.Collections.Hashtable] $General, [string] $tref, [System.Collections.Hashtable] $ref_content_map, [Microsoft.PowerShell.Commands.WebRequestSession] $session)
{
    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"

    if(-Not $ref_content_map.$tref){
        $headers = @{
            "content-type"="application/json";
            "referer"="https://$($General.HostAddress)";
            "x-csrftoken"=$($session.Cookies.GetCookies("https://$($General.HostAddress)")["csrftoken"].Value)
        }
		$resp_obj = Invoke-AviRestMethod -Uri $tref -Method Get -Headers $headers -ContentType "application/json" -WebSession $session -TimeoutSec 300
		$response = $resp_obj.response
		$ref_content_map.$tref = $response.name
        Write-VenDebugLog "Added tenant name to cache: [$($ref_content_map.$tref)]"
    }
    else {
        Write-VenDebugLog "Tenant name retrieved from cache: [$($ref_content_map.$tref)]"
    }
    return $ref_content_map.$tref
}

function Get-Certificate-By-Ref([System.Collections.Hashtable] $General, [string] $ssl_ref, [System.Collections.Hashtable] $ref_content_map, [Microsoft.PowerShell.Commands.WebRequestSession] $session)
{
    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"

    if(-Not $ref_content_map.$ssl_ref){
        $headers = @{
            "content-type"="application/json";
            "referer"="https://$($General.HostAddress)";
            "x-csrftoken"=$($session.Cookies.GetCookies("https://$($General.HostAddress)")["csrftoken"].Value)
        }
		$resp_obj = Invoke-AviRestMethod -Uri $ssl_ref -Method Get -Headers $headers -ContentType "application/json" -WebSession $session -TimeoutSec 300
		$response = $resp_obj.response
		$ref_content_map.$ssl_ref = $response.certificate.certificate
        Write-VenDebugLog "Added certificate to cache: [$($ssl_ref)]"
    }
    else {
        Write-VenDebugLog "Certificate retrieved from cache: [$($ssl_ref)]"
    }
    return $ref_content_map.$ssl_ref
}

# modified - add a function to perform certificate filename lookup
function Get-Cert-Name-By-Ref([System.Collections.Hashtable] $General, [string] $ssl_ref, [System.Collections.Hashtable] $ref_content_map, [Microsoft.PowerShell.Commands.WebRequestSession] $session)
{
    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"

    $ssl_name_ref = "$($ssl_ref)/name"
    if(-Not $ref_content_map.$ssl_name_ref){
        $headers = @{
            "content-type"="application/json";
            "referer"="https://$($General.HostAddress)";
            "x-csrftoken"=$($session.Cookies.GetCookies("https://$($General.HostAddress)")["csrftoken"].Value)
        }
		$resp_obj = Invoke-AviRestMethod -Uri $ssl_ref -Method Get -Headers $headers -ContentType "application/json" -WebSession $session -TimeoutSec 300
		$response = $resp_obj.response
		$ref_content_map.$ssl_name_ref = $response.name
        Write-VenDebugLog "Added filename to cache: [$($ref_content_map.$ssl_name_ref)]"
    }
    else {
        Write-VenDebugLog "Filename retrieved from cache: [$($ref_content_map.$ssl_name_ref)]"
    }
    return $ref_content_map.$ssl_name_ref
}

function Get-IPv4-VIP([System.Collections.Hashtable] $General, $vs, [Microsoft.PowerShell.Commands.WebRequestSession] $session)
{
    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"

    $headers = @{
        "content-type"="application/json";
        "referer"="https://$($General.HostAddress)";
        "x-csrftoken"=$($session.Cookies.GetCookies("https://$($General.HostAddress)")["csrftoken"].Value)
    }
	$resp_obj = Invoke-AviRestMethod -Uri $vs.vsvip_ref -Method Get -Headers $headers -ContentType "application/json" -WebSession $session -TimeoutSec 300
	$response = $resp_obj.response

    foreach ($vip_def in $response.vip) {
        if ($vip_def.floating_ip) {
            if ($vip_def.floating_ip.type -eq "V4") {
                Write-VenDebugLog "Floating IP for $($vs.name) is $($vip_def.floating_ip.addr)"
                return $vip_def.floating_ip.addr
            }
        }
        elseif ($vip_def.ip_address.type -eq "V4") {
            Write-VenDebugLog "No floating IP for $($vs.name). Private IP is $($vip_def.ip_address.addr)"
            return $vip_def.ip_address.addr
        }
    }
    Write-VenDebugLog "Returning... nothing?!"
}

function Get-SSL-Service-Port($vs_json){
    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"

    foreach($port in $vs_json.services){
        if($port.enable_ssl -eq $True){
            [string] $vsPort = $port.port
            Write-VenDebugLog "Service port for $($vs_json.name) is $($vsPort)"
			return $vsPort
        }
    }
    Write-VenDebugLog "Returning... nothing?!"
}

function Get-CACertName( [System.Security.Cryptography.X509Certificates.X509Certificate2] $cert )
{
    # name should not have any non-alphanumeric characters including whitespace
    $alphanumeric = '[^a-zA-Z0-9]'
    
    # use GetNameInfo to be consistent with Microsoft's naming
    $name = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
    $name = $name -replace $alphanumeric
    
    # append the last 4 characters of the serial number in case there has been reissuance of the CA certificate
    return $name + "_" + $cert.SerialNumber.Substring($cert.SerialNumber.Length-4)
}


function Select-ErrorMessage( [Exception] $ex )
{
    try {
        $result = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($result)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $json = $reader.ReadToEnd() | ConvertFrom-Json
        
        if ( $json.error ) {
            return $json.error
        }
        else {
            return $ex.Message
        }
    }
    catch # the response is either not xml or not in the expected format
    {
        return $ex.Message
    }
}

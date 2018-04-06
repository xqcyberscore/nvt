###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_unauth_digital_cert_spoofing_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Microsoft Unauthorized Digital Certificates Spoofing Vulnerability (2728973)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation could allow remote attackers to use the
  certificates to spoof content, perform phishing attacks, or perform
  man-in-the-middle attacks.
  Impact Level: System";
tag_affected = "Microsoft Windows XP x32 Edition Service Pack 3 and prior
  Microsoft Windows XP x64 Edition Service Pack 2 and prior
  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
  Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior";
tag_insight = "Microsoft certificate authorities, which are stored outside the recommended
  secure storage practices can be misused. An attacker could use these
  certificates to spoof content, perform phishing attacks, or perform
  man-in-the-middle attacks.";
tag_solution = "Apply the Patch from below link,
  http://support.microsoft.com/kb/2728973";
tag_summary = "This host is installed with Microsoft Windows operating system and
  is prone to Spoofing vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802912");
  script_version("$Revision: 9352 $");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-07-12 17:17:25 +0530 (Thu, 12 Jul 2012)");
  script_name("Microsoft Unauthorized Digital Certificates Spoofing Vulnerability (2728973)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2728973");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/advisory/2728973");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable Initialization
certs = "";
cert = "";
flag = FALSE;

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3, win7:2,
                   win7x64:2, win2008:3, win2008r2:2) <= 0){
  exit(0);
}

## Untrusted Certificates Path
key = "SOFTWARE\Microsoft\SystemCertificates\Disallowed\Certificates\";
if(!registry_key_exists(key:key)) {
  exit(0);
}

## Get System Path
sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

##Fetch the version of 'advapi32.dll'
fileVer = fetch_file_version(sysPath, file_name:"advpack.dll");
if(!fileVer){
  exit(0);
}

## The invalid certificates and their thumbprints
certs = make_list(
        ## Microsoft Genuine Windows Phone Public Preview CA01
        "E38A2B7663B86796436D8DF5898D9FAA6835B238",
        ## Microsoft IPTVe CA
        "BED412B1334D7DFCEBA3015E5F9F905D571C45CF",
        ## Microsoft Online CA001
        "A1505D9843C826DD67ED4EA5209804BDBB0DF502",
        ## Microsoft Online Svcs BPOS APAC CA1
        "D43153C8C25F0041287987250F1E3CABAC8C2177",
        ## Microsoft Online Svcs BPOS APAC CA2
        "D8CE8D07F9F19D2569C2FB854401BC99C1EB7C3B",
        ##Microsoft Online Svcs BPOS APAC CA3
        "E95DD86F32C771F0341743EBD75EC33C74A3DED9",
        ##Microsoft Online Svcs BPOS APAC CA4
        "3A26012171855D4020C973BEC3F4F9DA45BD2B83",
        ## Microsoft Online Svcs BPOS APAC CA5
        "D0BB3E3DFBFB86C0EEE2A047E328609E6E1F185E",
        ## Microsoft Online Svcs BPOS APAC CA6
        "08738A96A4853A52ACEF23F782E8E1FEA7BCED02",
        ## Microsoft Online Svcs BPOS CA1
        "7613BF0BA261006CAC3ED2DDBEF343425357F18B",
        ## Microsoft Online Svcs BPOS CA2
        "587B59FB52D8A683CBE1CA00E6393D7BB923BC92",
        ## Microsoft Online Svcs BPOS CA2
        "4ED8AA06D1BC72CA64C47B1DFE05ACC8D51FC76F",
        ## Microsoft Online Svcs BPOS CA2
        "F5A874F3987EB0A9961A564B669A9050F770308A",
        ## Microsoft Online Svcs BPOS EMEA CA1
        "A35A8C727E88BCCA40A3F9679CE8CA00C26789FD",
        ## Microsoft Online Svcs BPOS EMEA CA2
        "E9809E023B4512AA4D4D53F40569C313C1D0294D",
        ## Microsoft Online Svcs BPOS EMEA CA3
        "A7B5531DDC87129E2C3BB14767953D6745FB14A6",
        ## Microsoft Online Svcs BPOS EMEA CA4
        "330D8D3FD325A0E5FDDDA27013A2E75E7130165F",
        ## Microsoft Online Svcs BPOS EMEA CA5
        "09271DD621EBD3910C2EA1D059F99B8181405A17",
        ## Microsoft Online Svcs BPOS EMEA CA6
        "838FFD509DE868F481C29819992E38A4F7082873",
        ## Microsoft Online Svcs CA1
        "23EF3384E21F70F034C467D4CBA6EB61429F174E",
        ## Microsoft Online Svcs CA1
        "A221D360309B5C3C4097C44CC779ACC5A9845B66",
        ## Microsoft Online Svcs CA3
        "8977E8569D2A633AF01D0394851681CE122683A6",
        ## Microsoft Online Svcs CA3
        "374D5B925B0BD83494E656EB8087127275DB83CE",
        ## Microsoft Online Svcs CA4
        "6690C02B922CBD3FF0D0A5994DBD336592887E3F",
        ## Microsoft Online Svcs CA4
        "5D5185DF1EB7DC76015422EC8138A5724BEE2886",
        ## Microsoft Online Svcs CA5
        "A81706D31E6F5C791CD9D3B1B9C63464954BA4F5",
        ## Microsoft Online Svcs CA5
        "4DF13947493CFF69CDE554881C5F114E97C3D03B",
        ## Microsoft Online Svcs CA6
        "09FF2CC86CEEFA8A8BB3F2E3E84D6DA3FABBF63E"
        );

## Check if certificates are added by checking registry key
foreach cert (certs)
{
  if(! registry_key_exists(key: key+cert))
  {
    flag = TRUE;
    break;
  }
}


if(flag && version_is_less(version:fileVer, test_version:"6.0.2600.0")){
  security_message(0);
}

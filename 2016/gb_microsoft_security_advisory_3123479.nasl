###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_microsoft_security_advisory_3123479.nasl 5460 2017-03-02 05:43:13Z antu123 $
#
# Microsoft Root Certificate Program SHA-1 Deprecation Advisory (3123479)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806663");
  script_version("$Revision: 5460 $");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-03-02 06:43:13 +0100 (Thu, 02 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-01-14 13:09:43 +0530 (Thu, 14 Jan 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Microsoft Root Certificate Program SHA-1 Deprecation Advisory (3123479)");

  script_tag(name: "summary" , value:"This host is missing an important security
  update according to Microsoft advisory (3123479).");

  script_tag(name: "vuldetect" , value: "Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name: "insight" , value: "An update is available that aims to warn
  customers in assessing the risk of certain applications that use X.509 digital
  certificates that are signed using the SHA-1 hashing algorithm.");

  script_tag(name: "impact" , value: "Successful exploitation will allow
  attackers to take advantage of weakness of the SHA-1 hashing algorithm that
  exposes it to collision attacks.

  Impact Level: System");

  script_tag(name: "affected" , value:"
  Microsoft Windows 8 x32/x64
  Microsoft Windows 10 x32/x64
  Microsoft Windows 8.1 x32/x64
  Microsoft Windows Server 2012/2012R2
  Microsoft Windows 10 Version 1511 x32/x64.
  Microsoft Windows 7 x32/x64 Edition Service Pack 1
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1.");

  script_tag(name: "solution" , value: "Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://technet.microsoft.com/en-us/library/security/3123479");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://support.microsoft.com/en-in/kb/3123479");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/library/security/3123479");
  script_xref(name : "URL" , value : "http://social.technet.microsoft.com/wiki/contents/articles/32288.windows-enforcement-of-authenticode-code-signing-and-timestamping.aspx");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

#Hotfix check
if(hotfix_missing(name:"3197869") == 0){
  exit(0);
}

## Variables Initialization
sysPath = "";
dllVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, win8:1, win8x64:1,
                   win2012:1, win2012R2:1, win8_1:1, win8_1x64:1,
                   win2008:3, win10:1, win10x64:1) <= 0){
  exit(0);
}

key = "SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CertDllCreateCertificateChainEngine\Config\Default";

#After applying patch:
#Key added:
#HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CertDllCreateCertificateChainEngine\Config\Default
# Item WeakSha1ThirdPartyAfterTime and WeakSha1ThirdPartyFlags

#After removing patch
#Key deleted:
#HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CertDllCreateCertificateChainEngine\Config\Default
# Item WeakSha1ThirdPartyAfterTime and WeakSha1ThirdPartyFlags

wshatpat = registry_get_binary(key:key, item:"WeakSha1ThirdPartyAfterTime");
wshatpf = registry_get_dword(key:key, item:"WeakSha1ThirdPartyFlags");

if(!wshatpat || !wshatpf)
{
  report = 'Registry Entry Checked: ' + key + "\WeakSha1ThirdPartyAfterTime and " + key + "\WeakSha1ThirdPartyFlags" + '\n' +
           'Fix:                    Apply Updates\n' ;
  security_message(data:report);
  exit(0);
}

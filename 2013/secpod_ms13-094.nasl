###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-094.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Microsoft Outlook Information Disclosure Vulnerability (2894514)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903413");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-3905");
  script_bugtraq_id(63603);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-11-13 09:27:15 +0530 (Wed, 13 Nov 2013)");
  script_name("Microsoft Outlook Information Disclosure Vulnerability (2894514)");

  tag_summary =
"This host is missing an important security update according to
Microsoft Bulletin MS13-094.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"The flaw is due to an error during the expansion of the S/MIME certificate
metadata when validating the X.509 certificate chain and can be exploited
to gain knowledge IP addresses and open TCP ports from the host and the
connected LAN via a specially crafted S/MIME certificate sent in an email.";

  tag_impact =
"Successful exploitation will allow remote attackers to disclose certain
sensitive information.

Impact Level: Application ";

  tag_affected =
"Microsoft Outlook 2013
Microsoft Outlook 2007 Service Pack 3 and prior
Microsoft Outlook 2010 Service Pack 2 and prior";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and update
mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms13-094";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/55574");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1029328");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2825644");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2837597");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2837618");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms13-094");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Outlook/Version");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

# Variable Initialization
outlookVer = "";

## Check for Office outlook 2013 and 2010
outlookVer = get_kb_item("SMB/Office/Outlook/Version");
if(outlookVer && outlookVer =~ "^(14|15)\..*")
{
  if(version_in_range(version:outlookVer, test_version:"14.0", test_version2:"14.0.7109.4999") ||
     version_in_range(version:outlookVer, test_version:"15.0", test_version2:"15.0.4551.1003"))
  {
    security_message(0);
    exit(0);
  }
}

if(outlookVer && outlookVer =~ "^12\..*")
{
  ## Office outlook
  outlookFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                              "\App Paths\OUTLOOK.EXE", item:"Path");
  if(outlookFile)
  {
    outlookVer = fetch_file_version(sysPath:outlookFile, file_name:"Exsec32.dll");
    if(outlookVer)
    {
      if(version_in_range(version:outlookVer, test_version:"12.0", test_version2:"12.0.6685.4999")){
        security_message(0);
      }
    }
  }
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_auth_bypass_vuln.nasl 2013-12-31 17:01:32Z dec$
#
# Apple Mac OS X Authentication Bypass Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804184";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 9935 $");
  script_cve_id("CVE-2013-5163");
  script_bugtraq_id(62812);
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-05-23 15:15:24 +0200 (Wed, 23 May 2018) $");
  script_tag(name:"creation_date", value:"2013-12-31 20:51:30 +0530 (Tue, 31 Dec 2013)");
  script_name("Apple Mac OS X Authentication Bypass Vulnerability");

  tag_summary =
"This host is running Apple Mac OS X and is prone to authentication bypass
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaw is due to a logic error in the way the program verifies
authentication credentials.";

  tag_impact =
"Successful exploitation will allow a local attacker to bypass password
validation.

Impact Level: System";

  tag_affected =
"Mac OS X version 10.8.5 and prior.";

  tag_solution =
"Run Mac Updates and install OS X v10.8.5 Supplemental Update.
 For updates refer to http://support.apple.com/kb/HT5964.

*****
  NOTE: Ignore this warning, if above mentioned patch is already applied.
*****
";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod", value:"30"); ## Build information is not available
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT5964");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/123506/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
osName = "";
osVer = "";

## Get the OS name
osName = get_kb_item("ssh/login/osx_name");
if(!osName){
  exit (0);
}

## Get the OS Version
osVer = get_kb_item("ssh/login/osx_version");
if(!osVer){
 exit(0);
}

## Check for the Mac OS X
if("Mac OS X" >< osName)
{
  ## Check the affected OS versions
  if(version_in_range(version:osVer, test_version:"10.8.0", test_version2:"10.8.5"))
  {
    security_message(0);
    exit(0);
  }
}

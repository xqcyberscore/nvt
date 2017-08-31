###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_pgp_n_enc_desktop_bof_vuln.nasl 6515 2017-07-04 11:54:15Z cfischer $
#
# Symantec PGP Desktop and Encryption Desktop Buffer Overflow Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:symantec:pgp_desktop";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803888";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6515 $");
  script_cve_id("CVE-2012-6533");
  script_bugtraq_id(57835);
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-04 13:54:15 +0200 (Tue, 04 Jul 2017) $");
  script_tag(name:"creation_date", value:"2013-09-06 13:18:19 +0530 (Fri, 06 Sep 2013)");
  script_name("Symantec PGP Desktop and Encryption Desktop Buffer Overflow Vulnerability");

  tag_summary =
"The host is installed with Symantec PGP/Encryption Desktop and is prone to
buffer overflow vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaws is due to an error in the pgpwded.sys driver when processing the
0x80022058 IOCTL.";

  tag_impact =
"Successful exploitation will allow remote unauthenticated attacker to gain
escalated privileges.

Impact Level: Application";

  tag_affected =
"Symantec PGP Desktop 10.0.x, 10.1.x, and 10.2.x,
Symantec Encryption Desktop 10.3.0 prior to 10.3.0 MP1 on
Microsoft Windows XP and Microsoft Windows Server 2003";

  tag_solution =
"Upgrade to version 10.3.0 MP1 or later,
For updates refer to http://www.symantec.com";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51762");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52219");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("General");
  script_dependencies("gb_pgp_desktop_detect_win.nasl");
  script_mandatory_keys("PGPDesktop_or_EncryptionDesktop/Win/Installed");
  exit(0);
}


include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");

## Variable Initialization
rpVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, win2003:3) <= 0){
  exit(0);
}

## Get Symantec PGP Desktop version
if(!rpVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID))
{
  ## Get Symantec Encryption Desktop version
  CPE = "cpe:/a:symantec:encryption_desktop";
  if(!rpVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
    exit(0);
  }
}

## Check for Symantec PGP/Encryption Desktop version
if(version_in_range(version:rpVer, test_version:"10.0", test_version2:"10.3.0.9059"))
{
  security_message(0);
  exit(0);
}

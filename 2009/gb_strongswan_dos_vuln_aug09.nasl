###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_strongswan_dos_vuln_aug09.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# strongSwan Denial Of Service Vulnerability - Aug09
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_solution = "Upgrade to version 2.8.11, 4.2.17, and 4.3.3 or apply patches.
  http://download.strongswan.org/patches/
  http://www.strongswan.org/download.htm

  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation allows attackers to crash pluto IKE daemon,
  corrupt memory and can cause denial of service.
  Impact Level: Application";
tag_affected = "strongSwan version 2.8 before 2.8.11, 4.2 before 4.2.17 and
  4.3 before 4.3.3";
tag_insight = "The flaw is due to an error in 'asn1_length()' function in the
  'libstrongswan/asn1/asn1.c' script. It does not properly handle
  X.509 certificates with crafted Relative Distinguished Names (RDNs).";
tag_summary = "This host has strongSwan and is prone to Denial of
  Service Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800673");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-08-06 06:50:55 +0200 (Thu, 06 Aug 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-2661");
  script_name("strongSwan Denial Of Service Vulnerability  - Aug09");

  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/383254.php");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2009/07/27/1");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_strongswan_detect.nasl");
  script_require_keys("StrongSwan/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("version_func.inc");

ssVer = get_kb_item("StrongSwan/Ver");
if(!ssVer){
  exit(0);
}
# Check version 2.8 to 2.8.10, 4.2 to 4.2.16, 4.3 to 4.3.2
if(version_in_range(version:ssVer, test_version:"2.8.0",test_version2:"2.8.10") ||
   version_in_range(version:ssVer, test_version:"4.2.0",test_version2:"4.2.16") ||
   version_in_range(version:ssVer, test_version:"4.3.0",test_version2:"4.3.2")){
  security_message(0);
}

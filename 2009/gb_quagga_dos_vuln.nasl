###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_quagga_dos_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Quagga Denial of Service Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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

tag_impact = "Successful exploitation will let the attacker crash the daemon by advertising
  specially crafted AS paths and cause denial of service.

  Impact level: Application";

tag_solution = "Apply the security update with the patch 0.99.10-1lenny2 for stable versions.
  Apply the security update with the patch 0.99.11-2 for unstable versions.
  http://www.debian.org/security/2009/dsa-1788

  *****
  NOTE: Please ignore the warning if patch has been already applied.
  *****";

tag_affected = "Quagga version 0.99.11 and prior";
tag_insight = "This flaw is due to an assertion error in the BGP daemon while handling
  an AS path containing multiple 4 byte AS numbers.";
tag_summary = "This host is installed with Quagga for Linux and is prone to
  Denial of Service Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800710");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-05-13 10:01:19 +0200 (Wed, 13 May 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_bugtraq_id(34817);
  script_cve_id("CVE-2009-1572");
  script_name("Quagga Denial of Service Vulnerability");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/34999");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2009/05/01/2");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_quagga_detect.nasl");
  script_require_keys("Quagga/Ver");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "impact" , value : tag_impact);
  exit(0);
}


include("version_func.inc");

quaggaVer = get_kb_item("Quagga/Ver");
if(quaggaVer == NULL){
  exit(0);
}

# Grep for Quagga version 0.99.11 and prior.
if(version_is_less_equal(version:quaggaVer, test_version:"0.99.11")){
  security_message(0);
}

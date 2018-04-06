###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_amarok_mult_vuln_lin.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Amarok Player Multiple Vulnerabilities
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow attacker to execute malicious arbitrary
  codes or can cause heap overflow in the context of the application.";
tag_affected = "Amarok Player version prior to 2.0.1.1 on Linux";
tag_insight = "Multiple flaws are due to integer overflow errors within the
  Audible::Tag::readTag function in src/metadata/audible/audibletag.cpp. This
  can be exploited via specially crafted Audible Audio files with a large nlen
  or vlen Tag value.";
tag_solution = "Upgrade to the latest version 2.0.1.1
  http://amarok.kde.org";
tag_summary = "This host is installed with Amarok Player for Linux and is prone
  to Multiple Vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900431");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-01-22 12:00:13 +0100 (Thu, 22 Jan 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_bugtraq_id(33210);
  script_cve_id("CVE-2009-0135", "CVE-2009-0136");
  script_name("Amarok Player Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://amarok.kde.org/de/node/600");
  script_xref(name : "URL" , value : "http://secunia.com/Advisories/33505");
  script_xref(name : "URL" , value : "http://trapkit.de/advisories/TKADV2009-002.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_amarok_detect_lin.nasl");
  script_require_keys("Amarok/Linux/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

amarokVer = get_kb_item("Amarok/Linux/Ver");
if(!amarokVer){
  exit(0);
}

# Grep for Amarok Player version prior to 2.0.1.1
if(version_is_less(version:amarokVer, test_version:"2.0.1.1")){
  security_message(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_mult_vuln_jun09_1.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Apple Safari Multiple Vulnerabilities June-09 (Windows) - I
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

tag_impact = "Successful exploitation will let the attacker execute arbitrary code, bypass
  security restrictions, sensitive information disclosure, XSS attacks, execute
  JavaScript code, DoS attack and can cause other attacks.
  Impact Level: System/Application";
tag_affected = "Apple Safari version prior to 4.0 on Windows.";
tag_insight = "Refer to the reference links for more information on the vulnerabilities.";
tag_solution = "Upgrade to Safari version 4.0
  http://www.apple.com/support/downloads";
tag_summary = "This host is installed with Apple Safari Web Browser and is prone to
  to multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800814");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-06-16 15:11:01 +0200 (Tue, 16 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1700", "CVE-2009-1701", "CVE-2009-1702", "CVE-2009-1703",
                "CVE-2009-1704", "CVE-2009-1705", "CVE-2009-1706", "CVE-2009-1707",
                "CVE-2009-1708", "CVE-2009-1709", "CVE-2009-1710", "CVE-2009-1711",
                "CVE-2009-1712", "CVE-2009-1713", "CVE-2009-1714", "CVE-2009-1715",
                "CVE-2009-1716", "CVE-2009-1718", "CVE-2009-2027");
  script_bugtraq_id(35283, 35325, 35308, 35310, 35384, 35272, 35260);
  script_name("Apple Safari Multiple Vulnerabilities June-09 (Windows) - I");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT3613");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35379");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1522");
  script_xref(name : "URL" , value : "http://scary.beasts.org/security/CESA-2009-006.html");
  script_xref(name : "URL" , value : "http://scary.beasts.org/security/CESA-2009-008.html");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/published");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-09-034");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce/2009/jun/msg00002.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_reg_enum.nasl",
                      "secpod_apple_safari_detect_win_900003.nasl");
  script_require_keys("AppleSafari/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

safariVer = get_kb_item("AppleSafari/Version");
if(!safariVer){
  exit(0);
}

# Check for Apple Safari Version < 4.0
if(version_is_less(version:safariVer, test_version:"4.0")){
  security_message(0);
}

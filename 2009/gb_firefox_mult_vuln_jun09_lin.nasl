###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_mult_vuln_jun09_lin.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Mozilla Firefox Multiple Vulnerabilities Jun-09 (Linux)
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

tag_impact = "Successful exploitation could result in remote arbitrary JavaScript code
  execution, spoofing attacks, sensitive information disclosure, and can cause
  denial of service.
  Impact Level: System/Application";
tag_summary = "The host is installed with Firefox Browser, which is prone to
  multiple vulnerabilities.";

tag_affected = "Firefox version prior to 3.0.11 on Linux.";
tag_insight = "Multiple flaws are reported in Mozilla Firefoz. For more information refer
  to the reference links.";
tag_solution = "Upgrade to Firefox version 3.0.11
  http://www.mozilla.com/en-US/firefox/all-older.html";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800637");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-06-16 15:11:01 +0200 (Tue, 16 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1832", "CVE-2009-1833", "CVE-2009-1834", "CVE-2009-1835",
                "CVE-2009-1836", "CVE-2009-1837", "CVE-2009-1838", "CVE-2009-1839",
                "CVE-2009-1840", "CVE-2009-1841", "CVE-2009-1392", "CVE-2009-2043",
                "CVE-2009-2044", "CVE-2009-2061", "CVE-2009-2065");
  script_bugtraq_id(35326, 35360, 35280);
  script_name("Mozilla Firefox Multiple Vulnerability Jun-09 (Linux)");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_require_keys("Firefox/Linux/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/504214");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1572");
  script_xref(name : "URL" , value : "http://research.microsoft.com/apps/pubs/default.aspx?id=79323");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-24.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-25.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-26.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-27.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-28.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-29.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-30.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-31.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-32.html");
  script_xref(name : "URL" , value : "http://research.microsoft.com/pubs/79323/pbp-final-with-update.pdf");
  exit(0);
}


include("version_func.inc");

firefoxVer = get_kb_item("Firefox/Linux/Ver");
# Check for Fireox version < 3.0.11
if(firefoxVer != NULL)
{
  if(version_is_less(version:firefoxVer ,test_version:"3.0.11")){
    security_message(0);
  }
}

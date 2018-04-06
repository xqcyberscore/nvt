###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_dos_vuln_nov09_lin.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Mozilla Firefox Denial Of Service Vulnerability Nov-09 (Linux)
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

tag_impact = "Denial of Service or arbitrary code execution.
  Impact Level: Application/System";
tag_affected = "Firefox version 3.0 before 3.0.15 on Linux.";
tag_insight = "A memory corruption error in layout/base/nsCSSFrameConstructor.cpp in the
  browser engine can be exploited to potentially execute arbitrary code or
  crash the browser.";
tag_solution = "Upgrade to Firefox version 3.0.15
  http://www.mozilla.com/en-US/firefox/all.html";
tag_summary = "This host is installed with Mozilla Firefox and is prone to Denial
  of Service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801135");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-11-02 14:39:30 +0100 (Mon, 02 Nov 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3382");
  script_bugtraq_id(36866);
  script_name("Mozilla Firefox Denial Of Service Vulnerability Nov-09 (Linux)");
  script_xref(name : "URL" , value : "https://bugzilla.mozilla.org/show_bug.cgi?id=514960");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-64.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_require_keys("Firefox/Linux/Ver");
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

ffVer = get_kb_item("Firefox/Linux/Ver");
if(!ffVer){
  exit(0);
}

# Check for Firefox version 3.0 < 3.0.15
if(version_in_range(version:ffVer, test_version:"3.0", test_version2:"3.0.14")) {
  security_message(0);
}

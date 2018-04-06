###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_dos_vuln_may09_lin.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Mozilla Firefox DoS Vulnerability May-09 (Linux)
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

tag_impact = "Successful exploitation will let attackers to execute arbitrary code which
  results in memory corruption.
  Impact Level: Application";
tag_affected = "Firefox version prior to 3.0.10 on Linux.";
tag_insight = "The flaw is due to error in nsTextFrame::ClearTextRun function in
  layout/generic/nsTextFrameThebes.cpp via unspecified vectors.";
tag_solution = "Upgrade to Firefox version 3.0.10
  http://www.mozilla.com/en-US/firefox/all.html";
tag_summary = "The host is installed with Mozilla Firefox browser and is prone
  to Denial of Service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800398");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-05-07 14:39:04 +0200 (Thu, 07 May 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1313");
  script_bugtraq_id(34743);
  script_name("Mozilla Firefox DoS Vulnerability May-09 (Linux)");
  script_xref(name : "URL" , value : "https://rhn.redhat.com/errata/RHSA-2009-0449.html");
  script_xref(name : "URL" , value : "https://bugzilla.mozilla.org/show_bug.cgi?id=490233");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Apr/1022126.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-23.html");

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

# Grep for Firefox version < 3.0.10
if(version_is_less(version:ffVer, test_version:"3.0.10")){
  security_message(0);
}

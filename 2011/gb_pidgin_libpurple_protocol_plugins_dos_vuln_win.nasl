###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pidgin_libpurple_protocol_plugins_dos_vuln_win.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Pidgin Libpurple Protocol Plugins Denial of Service Vulnerabilities (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation allows remote attackers to execute arbitrary code,
  obtain sensitive information or cause a denial of service.
  Impact Level: System/Application";
tag_affected = "Pidgin versions prior to 2.10.0";
tag_insight = "Multiple flaws are due to,
  - An error in the IRC protocol plugin in libpurple when handling WHO
    responses with special characters in the nicknames.
  - An error in the MSN protocol plugin when handling HTTP 100 responses.
  - Improper handling of 'file:// URI', allows to execute the file when user
    clicks on a file:// URI in a received IM.";
tag_solution = "Upgrade to Pidgin version 2.10.0 or later.
  For updates refer to http://pidgin.im/download/windows/";
tag_summary = "This host is installed with Pidgin and is prone to denial of
  service vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802331");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-09-09 17:36:48 +0200 (Fri, 09 Sep 2011)");
  script_cve_id("CVE-2011-2943", "CVE-2011-3184", "CVE-2011-3185");
  script_bugtraq_id(49268);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Pidgin Libpurple Protocol Plugins Denial of Service Vulnerabilities (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45663");
  script_xref(name : "URL" , value : "http://pidgin.im/news/security/?id=53");
  script_xref(name : "URL" , value : "http://pidgin.im/news/security/?id=54");
  script_xref(name : "URL" , value : "http://pidgin.im/news/security/?id=55");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1025961");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_pidgin_detect_win.nasl");
  script_require_keys("Pidgin/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Get Pidgin Version from KB
pidginVer = get_kb_item("Pidgin/Win/Ver");

if(pidginVer != NULL)
{
  ## Check for Pidgin Versions Prior to 2.10.0
  if(version_is_less(version:pidginVer, test_version:"2.10.0")){
    security_message(0);
  }
}

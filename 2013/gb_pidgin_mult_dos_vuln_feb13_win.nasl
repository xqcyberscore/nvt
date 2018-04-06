###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pidgin_mult_dos_vuln_feb13_win.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Pidgin Multiple Denial of Service Vulnerabilities -Feb13 (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation allows remote attackers to execute arbitrary code,
  overwrite arbitrary local files or cause a denial of service.
  Impact Level: System/Application";

tag_affected = "Pidgin versions prior to 2.10.7";
tag_insight = "Multiple flaws are due to,
  - MXit protocol in libpurple saves an image to local disk using a filename.
  - Buffer overflow in http.c via HTTP header.
  - Does not properly terminate long user IDs, in sametime.c in libpurple.
  - upnp.c in libpurple fails to null-terminate strings in UPnP responses.";
tag_solution = "Upgrade to Pidgin version 2.10.7 or later.
  For updates refer to http://pidgin.im/download/windows/";
tag_summary = "This host is installed with Pidgin and is prone to multiple denial of
  service vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803308");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-0271","CVE-2013-0272","CVE-2013-0273","CVE-2013-0274");
  script_bugtraq_id(57951,57952,57954);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-02-20 19:21:44 +0530 (Wed, 20 Feb 2013)");
  script_name("Pidgin Multiple Denial of Service Vulnerabilities -Feb13 (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52178");
  script_xref(name : "URL" , value : "http://www.pidgin.im/news/security/?id=65");
  script_xref(name : "URL" , value : "http://www.pidgin.im/news/security/?id=66");
  script_xref(name : "URL" , value : "http://www.pidgin.im/news/security/?id=67");
  script_xref(name : "URL" , value : "http://www.pidgin.im/news/security/?id=68");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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

## Variable Initialization
pidginVer = "";

## Get Pidgin Version from KB
pidginVer = get_kb_item("Pidgin/Win/Ver");

if(pidginVer != NULL)
{
  ## Check for Pidgin Versions Prior to 2.10.7
  if(version_is_less(version:pidginVer, test_version:"2.10.7"))
  {
    security_message(0);
    exit(0);
  }
}

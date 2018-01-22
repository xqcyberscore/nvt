###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_mult_vuln_aug10_win.nasl 8457 2018-01-18 07:58:32Z teissa $
#
# Opera Browser Multiple Vulnerabilities August-10 (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow remote attackers to bypass certain security
  protections, execute arbitrary code, or cause denial-of-service conditions.
  Impact Level: Application";
tag_affected = "Opera Web Browser Version prior to 10.61";
tag_insight = "The multiple flaws are cause due to:
  - An error in the processing of painting operations on a canvas while
    certain transformations are being applied, which can be exploited to cause
    a heap-based buffer overflow.
  - An error when displaying the download dialog, which could allow attackers
    to trick a user into running downloaded executables.
  - An error when previewing a news feed, which can be exploited to execute
    script code and automatically subscribe the user to the feed.";
tag_solution = "Upgrade to Opera Web Browser Version 10.61 or later,
  For updates refer to http://www.opera.com/download/";
tag_summary = "The host is installed with Opera Browser and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801257");
  script_version("$Revision: 8457 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-08-16 09:09:42 +0200 (Mon, 16 Aug 2010)");
  script_cve_id("CVE-2010-3021", "CVE-2010-3020", "CVE-2010-3019", "CVE-2010-2576");
  script_bugtraq_id(42407);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Opera Browser Multiple Vulnerabilities August-10 (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40120");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/966/");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/967/");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/968/");
  script_xref(name : "URL" , value : "http://www.opera.com/docs/changelogs/windows/1061/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_opera_detection_win_900036.nasl");
  script_require_keys("Opera/Win/Version");
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

## Get Opera Version from KB
ver = get_kb_item("Opera/Win/Version");

if(ver)
{
  ## Grep for Opera Versions prior to 10.61
  if(version_in_range(version:ver, test_version:"10.0", test_version2:"10.60")){
    security_message(0);
  }
}

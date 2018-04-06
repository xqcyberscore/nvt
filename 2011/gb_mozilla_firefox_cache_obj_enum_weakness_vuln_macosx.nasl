###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_cache_obj_enum_weakness_vuln_macosx.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Mozilla Firefox Cache Objects History Enumeration Weakness Vulnerability (MAC OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation allows remote attackers to extraction
browser history by observing cache timing via crafted JavaScript code.

Impact Level: Application";

tag_affected = "Mozilla Firefox versions 8.0.1 and prior on MAC OS X";

tag_insight = "The flaw is caused due an error in handling cache objects and
can be exploited to enumerate visited sites.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host is installed with Mozilla Firefox and is prone to cache
objects history enumeration weakness vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802548");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2011-4688");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-12-09 17:53:11 +0530 (Fri, 09 Dec 2011)");
  script_name("Mozilla Firefox Cache Objects History Enumeration Weakness Vulnerability (MAC OS X)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47090");
  script_xref(name : "URL" , value : "http://lcamtuf.coredump.cx/cachetime/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_require_keys("Mozilla/Firefox/MacOSX/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

## Firefox Check
ffVer = get_kb_item("Mozilla/Firefox/MacOSX/Version");
if(ffVer)
{
  ## Grep for Firefox versions before 8.0.1
  if(version_is_less_equal(version:ffVer, test_version:"8.0.1")){
    security_message(0);
  }
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_untrusted_search_path_vuln_win.nasl 3100 2016-04-18 14:41:20Z benallard $
#
# Mozilla Firefox Untrusted Search Path Vulnerability (Windows)
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

tag_impact = "Successful exploitation will let attackers to execute arbitrary code in the
  context of the affected application.
  Impact Level: System/Application";
tag_affected = "Mozilla Firefox version before 3.6.20";
tag_insight = "The flaw is due to error in 'ThinkPadSensor::Startup' allows local
  users to gain privileges by leveraging write access in an unspecified
  directory to place a Trojan horse DLL that is loaded into the running
  Firefox process.";
tag_solution = "Upgrade to Mozilla Firefox version 3.6.20 or later,
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html";
tag_summary = "The host is installed with Mozilla firefox and is prone to
  untrusted search path vulnerability.";

if(description)
{
  script_id(802149);
  script_version("$Revision: 3100 $");
  script_tag(name:"last_modification", value:"$Date: 2016-04-18 16:41:20 +0200 (Mon, 18 Apr 2016) $");
  script_tag(name:"creation_date", value:"2011-09-09 17:36:48 +0200 (Fri, 09 Sep 2011)");
  script_cve_id("CVE-2011-2980");
  script_bugtraq_id(49217);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Firefox Untrusted Search Path Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2011/mfsa2011-30.html");

  script_summary("Check for the version of Mozilla Firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_require_keys("Firefox/Win/Ver");
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

# Firefox Check
ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  # Grep for Firefox version
  if(version_is_less(version:ffVer, test_version:"3.6.20")){
     security_message(0);
     exit(0);
  }
}

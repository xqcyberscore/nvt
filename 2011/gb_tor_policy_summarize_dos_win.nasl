###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tor_policy_summarize_dos_win.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Tor Directory Authority 'policy_summarize' Denial of Service Vulnerability (Windows)
#
# Authors:
# N Shashi Kiran <nskiran@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code in the context of the user running the application. Failed exploit
  attempts will likely result in denial-of-service conditions.

  Impact level: Application";

tag_affected = "Tor version prior to 0.2.1.30 on Windows.";
tag_insight = "The flaw is caused by an boundary error within the policy_summarize function
  in Tor, which can be exploited to crash a Tor directory authority.";
tag_solution = "Upgrade to Tor version 0.2.1.30 or later
  http://www.torproject.org/download/download.html.en";
tag_summary = "This host is installed with Tor and is prone to buffer overflow
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802300");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-06-20 15:22:27 +0200 (Mon, 20 Jun 2011)");
  script_cve_id("CVE-2011-1924");
  script_bugtraq_id(46618);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Tor Directory Authority 'policy_summarize' Denial of Service Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43548");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_tor_detect_win.nasl");
  script_require_keys("Tor/Win/Ver");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

torVer = get_kb_item("Tor/Win/Ver");
if(!torVer){
  exit(0);
}

torVer = ereg_replace(pattern:"-", replace:".", string:torVer);

if(version_is_less(version:torVer, test_version:"0.2.1.30")){
  security_message(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_flock_xss_win.nasl 8250 2017-12-27 07:29:15Z teissa $
#
# Flock Browser Malformed Bookmark Cross site scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow attackers to execute HTML code in the
  context of the affected browser, potentially allowing the attacker to steal
  cookie-based authentication credentials.
  Impact Level: Application";
tag_affected = "Flock versions 3.0 to 3.0.0.4093";
tag_insight = "The flaw is due to malformed favourite imported from an HTML file,
  imported from another browser, or manually created can bypass cross-origin
  protection, which has unspecified impact and attack vectors.";
tag_solution = "Upgrade to the Flock version 3.0.0.4094
  For updates refer to http://www.flock.com/";
tag_summary = "This host is installed with Flock browser and is prone to cross
  site scripting vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902313");
  script_version("$Revision: 8250 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-27 08:29:15 +0100 (Wed, 27 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-09-29 09:26:02 +0200 (Wed, 29 Sep 2010)");
  script_cve_id("CVE-2010-3202");
  script_bugtraq_id(42556);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Flock Browser Malformed Bookmark Cross site scripting Vulnerability");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("General");
  script_dependencies("gb_flock_detect_win.nasl");
  script_require_keys("Flock/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://flock.com/security/");
  script_xref(name : "URL" , value : "http://lostmon.blogspot.com/2010/08/flock-browser-3003989-malformed.html");
  exit(0);
}


include("version_func.inc");

flockVer = get_kb_item("Flock/Win/Ver");
if(!flockVer){
  exit(0);
}

# Check for Flock Version 3.x to 3.0.0.4093
if(version_in_range(version:flockVer, test_version:"3.0", test_version2:"3.0.0.4093")){
  security_message(0);
}

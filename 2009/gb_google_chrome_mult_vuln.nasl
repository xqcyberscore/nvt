###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln.nasl 4869 2016-12-29 11:01:45Z teissa $
#
# Google Chrome Multiple Vulnerabilities (Feb-09)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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

tag_impact = "Successful exploitation will let the attacker read the full URL and
  potentially other attributes or data from another frame in a different
  domain and can conduct cross site scripting attacks to gain users
  sensitive information and can also able to hijack legitimate user session
  and could gain sensitive information for the victim accounts.";
tag_affected = "Google Chrome version prior to 1.0.154.46";
tag_insight = "Multiple Flaws are due to,
  - an error exists in the V8 JavaScript engine while re-directing to
    another windows through iframe tag as it allows to bypass the same
    origin policy through a crafted iframe crafted script.
  - a flaw in the 'XMLHttpRequest' header which contains the cookie
    information of the logged user.";
tag_solution = "Upgrade Google Chrome to version 1.0.154.46 or later.
  http://www.google.com/chrome";
tag_summary = "This host is installed with Google Chrome and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(800229);
  script_version("$Revision: 4869 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-29 12:01:45 +0100 (Thu, 29 Dec 2016) $");
  script_tag(name:"creation_date", value:"2009-02-05 14:42:09 +0100 (Thu, 05 Feb 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-0276", "CVE-2009-0411");
  script_name("Google Chrome Multiple Vulnerabilities (Feb-09)");


  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_require_keys("GoogleChrome/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33754");
  script_xref(name : "URL" , value : "http://src.chromium.org/viewvc/chrome?view=rev&revision=8524");
  script_xref(name : "URL" , value : "http://src.chromium.org/viewvc/chrome?view=rev&revision=8529");
  script_xref(name : "URL" , value : "http://sites.google.com/a/chromium.org/dev/getting-involved/dev-channel/release-notes");
  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

#Grep for Chrome version prior to 1.0.154.46
if(version_is_less(version:chromeVer, test_version:"1.0.154.46")){
  security_message(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_mult_vuln_aug12_win.nasl 3047 2016-04-11 13:58:34Z benallard $
#
# Opera Multiple Vulnerabilities - August12 (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script code, disclose sensitive information, or cause a denial of service.
  Impact Level: Application";
tag_affected = "Opera version prior to 12.01 on Windows";
tag_insight = "- Multiple unspecified errors.
  - An error when certain characters in HTML documents are ignored under some
    circumstances, which allows to conduct XSS attacks.
  - The improper implementation of download dialog feature, which allows
    attackers to trick users into downloading and executing arbitrary files
    via a small window for the download dialog.
  - Fails to escape characters in DOM elements, which allows to conduct
    XSS attacks.
  - An error caused via a crafted web site on Lenovos 'Shop now' page.";
tag_solution = "Upgrade to Opera version 12.01 or later,
  For updates refer to http://www.opera.com/";
tag_summary = "This host is installed with Opera and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(803001);
  script_version("$Revision: 3047 $");
  script_bugtraq_id(54782, 54788, 54780);
  script_cve_id("CVE-2012-4142", "CVE-2012-4143", "CVE-2012-4144",
                "CVE-2012-4145", "CVE-2012-4146");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2016-04-11 15:58:34 +0200 (Mon, 11 Apr 2016) $");
  script_tag(name:"creation_date", value:"2012-08-08 10:50:33 +0530 (Wed, 08 Aug 2012)");
  script_name("Opera Multiple Vulnerabilities - August12 (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50044");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/1025/");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/1026/");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/1027/");
  script_xref(name : "URL" , value : "http://www.opera.com/docs/changelogs/windows/1201/");

  script_summary("Check for the version of Opera for Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

operaVer = "";

## Get Opera version from KB
operaVer = get_kb_item("Opera/Win/Version");
if(!operaVer){
  exit(0);
}

## Check for opera version is less than 12.01
if(version_is_less(version:operaVer, test_version:"12.01")){
  security_message(0);
}

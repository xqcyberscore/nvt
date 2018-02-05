###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_mult_vuln_june12_macosx.nasl 8649 2018-02-03 12:16:43Z teissa $
#
# Opera Multiple Vulnerabilities - June12 (Mac OS X)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script code, disclose sensitive information or spoof the originating URL
  of a trusted web site and carry out phishing-style attacks.
  Impact Level: System/Application";
tag_affected = "Opera version prior to 11.65 on Mac OS X";
tag_insight = "- An error when displaying preferences within a small window can be exploited
    to execute arbitrary code by tricking a user into entering a specific
    keyboard sequence.
  - An error when displaying pop-up windows can be exploited to execute script
    code by tricking a user into following a specific sequence of events.
  - An error when handling JSON resources can be exploited to bypass the cross
    domain policy restriction and disclose certain information to other sites.
  - An unspecified error can be exploited to display arbitrary content while
    showing the URL of a trusted web site in the address bar.
  - An error when handling page loads can be exploited to display arbitrary
    content while showing the URL of a trusted web site in the address.";
tag_solution = "Upgrade to Opera version 11.65 or 12 or later,
  For updates refer to http://www.opera.com/";
tag_summary = "The host is installed with Opera and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802647");
  script_version("$Revision: 8649 $");
  script_bugtraq_id(54011);
  script_cve_id("CVE-2012-3555", "CVE-2012-3556", "CVE-2012-3557", "CVE-2012-3558",
                "CVE-2012-3560");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-02-03 13:16:43 +0100 (Sat, 03 Feb 2018) $");
  script_tag(name:"creation_date", value:"2012-06-21 15:15:15 +0530 (Thu, 21 Jun 2012)");
  script_name("Opera Multiple Vulnerabilities - June12 (Mac OS X)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49533/");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/1018/");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/1019/");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/1020/");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/1021/");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/1022/");
  script_xref(name : "URL" , value : "http://www.opera.com/docs/changelogs/mac/1165/");
  script_xref(name : "URL" , value : "http://www.opera.com/docs/changelogs/mac/1200/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_opera_detect_macosx.nasl");
  script_require_keys("Opera/MacOSX/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

operaVer = "";

## Get Opera version from KB
operaVer = get_kb_item("Opera/MacOSX/Version");
if(!operaVer){
  exit(0);
}

## Check for opera version is less than 11.65
if(version_is_less(version:operaVer, test_version:"11.65")){
  security_message(0);
}

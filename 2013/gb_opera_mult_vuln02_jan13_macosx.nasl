###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_mult_vuln02_jan13_macosx.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Opera Multiple Vulnerabilities-02 Jan13 (Mac OS X)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation will let the attacker crash the browser leading to
  denial of service, execute the arbitrary code or disclose the information.
  Impact Level: System/Application";

tag_affected = "Opera version before 12.11 on Mac OS X";
tag_insight = "- An error in handling of error pages, can be used to guess local file paths.
  - An error when requesting pages using HTTP, causes a buffer overflow, which
    in turn can lead to a memory corruption and crash.";
tag_solution = "Upgrade to Opera version 12.11 or later,
  For updates refer to http://www.opera.com/";
tag_summary = "The host is installed with Opera and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803143");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2012-6468", "CVE-2012-6469");
  script_bugtraq_id(56594);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-01-07 15:36:59 +0530 (Mon, 07 Jan 2013)");
  script_name("Opera Multiple Vulnerabilities-02 Jan13 (Mac OS X)");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/1037/");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/1036/");
  script_xref(name : "URL" , value : "http://www.opera.com/docs/changelogs/unified/1212/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_opera_detect_macosx.nasl", "ssh_authorization_init.nasl");
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

## Check for opera versions prior to 12.11
if(version_is_less(version:operaVer, test_version:"12.11")){
  security_message(0);
}

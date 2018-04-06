###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_webkit_info_disc_vuln_win.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Apple Safari WebKit Information Disclosure Vulnerability (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation will allow attackers to gain access to
sensitive information and launch other attacks.

Impact Level: Application";

tag_affected = "Apple Safari versions 5.1.1 and prior.";

tag_insight = "The flaw is due to WebKit does not prevent capture of data about
the time required for image loading, which makes it easier for remote attackers
to determine whether an image exists in the browser cache via crafted
JavaScript code.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host is installed with Apple Safari web browser and is prone
to information disclosure vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802282");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2011-4692");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-12-09 11:11:11 +0530 (Fri, 09 Dec 2011)");
  script_name("Apple Safari WebKit Information Disclosure Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://oxplot.github.com/visipisi/visipisi.html");
  script_xref(name : "URL" , value : "http://lcamtuf.coredump.cx/cachetime/firefox.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_require_keys("AppleSafari/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

safVer = get_kb_item("AppleSafari/Version");
if(!safVer){
  exit(0);
}

## Grep for Apple Safari Versions 5.1.1 (5.34.51.22) and prior.
if(version_is_less_equal(version:safVer, test_version:"5.34.51.22")){
  security_message(0);
}

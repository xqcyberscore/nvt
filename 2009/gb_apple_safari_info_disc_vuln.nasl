###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_info_disc_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Apple Safari RSS Feed Information Disclosure Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful remote exploitation can potentially be exploited to gain access
  to sensitive information and launch other attacks.
  Impact Level: System.";
tag_affected = "Apple Safari 3.1.2 and prior on Windows.";
tag_insight = "Flaw is due an error generated in safari web browser while handling feed,
  feeds and feedsearch URL types for RSS feeds.";
tag_solution = "No solution or patch was made available for at least one year since disclosure
of this vulnerability. Likely none will be provided anymore. General solution
options are to upgrade to a newer release, disable respective features,
remove the product or replace the product by another one.
For updates refer to http://www.apple.com/support/downloads

A workaround is available to correct this issue.
- Download and install the RCDefaultApp preference pane.
- Open System Preferences and choose the Default Applications option.
- Select the 'URLs' tab in the window that appears.
- Choose the 'feed' URL type from the column on the left, and choose a
  different application or the '<disabled>' option.
- Repeat the previous step for the 'feeds' and 'feedsearch' URL types.";
tag_summary = "The host is running Apple Safari web browser which is prone
  to remote file access vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800506");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-01-19 13:47:40 +0100 (Mon, 19 Jan 2009)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_cve_id("CVE-2009-0123");
  script_bugtraq_id(33234);
  script_name("Apple Safari RSS Feed Information Disclosure Vulnerability");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/366491.php");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/47917");
  script_xref(name : "URL" , value : "http://brian.mastenbrook.net/display/27");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_require_keys("AppleSafari/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

safVer = get_kb_item("AppleSafari/Version");
if(!safVer){
  exit(0);
}

if(version_is_less_equal(version:safVer, test_version:"3.525.21.0")){
  security_message(0);
}

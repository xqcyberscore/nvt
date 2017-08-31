###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_allplayer_bof_vuln_nov14_win.nasl 6724 2017-07-14 09:57:17Z teissa $
#
# ALLPlayer Buffer Overflow Vulnerability - Nov14 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:allplayer:allplayer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805101");
  script_version("$Revision: 6724 $");
  script_cve_id("CVE-2013-7409");
  script_bugtraq_id(62926);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-14 11:57:17 +0200 (Fri, 14 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-11-21 11:25:38 +0530 (Fri, 21 Nov 2014)");
  script_name("ALLPlayer Buffer Overflow Vulnerability - Nov14 (Windows)");

  script_tag(name: "summary" , value:"This host is installed with ALLPlayer
  and is prone to buffer overflow vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help of
  detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Flaw is due to improper handling of M3U file.");

  script_tag(name: "impact" , value:"Successful exploitation will allow attackers
  to cause a buffer overflow, resulting in a denial of service or potentially
  allowing the execution of arbitrary code.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"ALLPlayer version 5.6.2 through 5.8.1
  on Windows");

  script_tag(name: "solution" , value:"No solution or patch was made available
  for at least one year since disclosure of this vulnerability. Likely none will
  be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another
  one.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"NoneAvailable");

  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/32074");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/28855");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/32041");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/29798");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/29549");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/125519");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/123554");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/124161");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/123986");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_allplayer_detect_win.nasl");
  script_mandatory_keys("ALLPlayer/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
playerVer = "";

## Get version
if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Grep for vulnerable version
if(version_in_range(version:playerVer, test_version:"5.6.2", test_version2:"5.8.1"))
{
  security_message(0);
  exit(0);
}

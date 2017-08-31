###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_winamp_mult_bof_sep14_win_vuln.nasl 6715 2017-07-13 09:57:40Z teissa $
#
# Winamp Libraries Multiple Buffer Overflow Vulnerability - Sep14
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:nullsoft:winamp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804845");
  script_version("$Revision: 6715 $");
  script_cve_id("CVE-2013-4694");
  script_bugtraq_id(60883);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-13 11:57:40 +0200 (Thu, 13 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-09-18 16:49:22 +0530 (Thu, 18 Sep 2014)");

  script_name("Winamp Libraries Multiple Buffer Overflow Vulnerability - Sep14");

  script_tag(name: "summary" , value:"This host is installed with Winamp and
  is prone to buffer overflow vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Flaw exist as user-supplied input is not
  properly validated when handling a specially crafted overly long Skins directory
  name.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to cause a denial of service or potentially allowing the execution
  of arbitrary code.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Winamp prior version 5.64 Build 3418");

  script_tag(name: "solution" , value:"Upgrade to Winamp version 5.64 Build 3418
  or later.");

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/85399");
  script_xref(name : "URL" , value : "http://forums.winamp.com/showthread.php?t=364291");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_family("Buffer overflow");
  script_dependencies("secpod_winamp_detect.nasl");
  script_mandatory_keys("Winamp/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

## Variable Initialization
version = "";

## Get the version
if(!version = get_app_version(cpe:CPE)){
  exit(0);
}

## Check the vulnerable version, less than 5.64 Build 3418 = 5.6.4.3418
if(version_is_less(version:version, test_version:"5.6.4.3418"))
{
  security_message(0);
  exit(0);
}

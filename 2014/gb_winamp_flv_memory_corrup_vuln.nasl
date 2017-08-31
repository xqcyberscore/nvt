###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_winamp_flv_memory_corrup_vuln.nasl 6769 2017-07-20 09:56:33Z teissa $
#
# Winamp '.flv' File Processing Memory Corruption Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.804826");
  script_version("$Revision: 6769 $");
  script_cve_id("CVE-2014-3442");
  script_bugtraq_id(67429);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-20 11:56:33 +0200 (Thu, 20 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-09-03 15:23:48 +0530 (Wed, 03 Sep 2014)");
  script_name("Winamp '.flv' File Processing Memory Corruption Vulnerability");

  tag_summary =
"This host is installed with Winamp and is prone to memory corruption
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaw is due to a memory corruption error when handling malicious '.flv'
files.";

  tag_impact =
"Successful exploitation will allow remote attackers to cause a denial of
service(memory corruption and crash).

Impact Level: Application";

  tag_affected =
"Winamp version 5.666 build 3516 and earlier.";

  tag_solution =
"No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/93173");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/126636");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("General");
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

## Check the vulnerable version, 5.666 build 3516= 5.6.6.3516
if(version_is_less_equal(version:version, test_version:"5.6.6.3516"))
{
  security_message(0);
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_core_ftp_le_client_remote_buffer_overflow_vuln.nasl 7174 2017-09-18 11:48:08Z asteins $
#
# Core FTP LE Client 'SSH/SFTP' Remote Buffer Overflow Vulnerability
# 
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:coreftp:core_ftp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810305");
  script_version("$Revision: 7174 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 13:48:08 +0200 (Mon, 18 Sep 2017) $");
  script_tag(name:"creation_date", value:"2016-12-08 12:40:39 +0530 (Thu, 08 Dec 2016)");
  script_name("Core FTP LE Client 'SSH/SFTP' Remote Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Core FTP Client
  and is prone to remote buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists when core ftp client
  does not handle long string of junk from the malicious FTP server
  using SSH/SFTP protocol.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  denial of service.

  Impact Level: System/Application.");

  script_tag(name:"affected", value:"Core FTP LE (Client) v2.2 build 1883.");

  script_tag(name:"solution", value:"Update to version 2.2 (build 1885). For updates refer to https://www.coreftp.com");
  
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40828");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_core_ftp_le_client_detect.nasl");
  script_mandatory_keys("Core/FTP/Client/Win/Ver");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

## Variable Initialization
ftpVer= "";

## Get version
if(!ftpVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Check For Version equal to 2.2.1796.0
if(version_is_equal(version:ftpVer, test_version:"2.2.1883.0"))
{
  report = report_fixed_ver(installed_version:ftpVer, fixed_version:"2.2.1885");
  security_message(data:report);
  exit(0);
}

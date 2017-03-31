###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_disk_savvy_login_buffer_overflow_vuln_oct.nasl 5083 2017-01-24 11:21:46Z cfi $
#
# Disk Savvy Enterprise 9.0.32 - Login Buffer Overflow (Windows)
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:disksavvy:disksavvy_enterprise_web_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107101");
  script_version("$Revision: 5083 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-01-24 12:21:46 +0100 (Tue, 24 Jan 2017) $");
  script_tag(name:"creation_date", value:"2016-12-05 11:19:11 +0530 (Mon, 05 Dec 2016)");
  script_name("Disk Savvy Enterprise 9.0.32 - Login Buffer Overflow (Windows)");
  script_tag(name: "summary" , value: "This host is installed with Disk Savvy Enterprise and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value: "Get the installed version with the
  help  of detection NVT and check if the version is vulnerable or not.");

  script_tag(name: "impact" , value: "Successful exploitation will allow attacker
  to elevate privileges from any account type and execute code.");

  script_tag(name: "affected" , value:"Disk Savvy Enterprise 9.0.32");

  script_tag(name: "solution" , value:"Until the time this script was written, no solution was still available .");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name: "URL" , value : "https://www.exploit-db.com/exploits/40854/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_disk_savvy_enterprise_server_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("DiskSavvy/Enterprise/Server/installed", "Host/runs_windows");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

dsVer = "";
dsPort = "";
report = "";

if (!dsPort = get_app_port(cpe:CPE)){
    exit(0);
}

if(!dsVer = get_app_version(cpe:CPE, port: dsPort)){
  exit(0);
}

if (version_is_equal(version: dsVer, test_version:"9.0.32"))
{
   report = report_fixed_ver( installed_version:dsVer, fixed_version:'See Vendor' );
   security_message(data:report, port: dsPort);
   exit(0);
}




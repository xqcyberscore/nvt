###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samba_smb1_memory_leak_vuln.nasl 8882 2018-02-20 10:35:37Z cfischer $
#
# Samba Server 'SMB1' Memory Information Leak Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811905");
  script_version("$Revision: 8882 $");
  script_cve_id("CVE-2017-12163");
  script_bugtraq_id(100925);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-02-20 11:35:37 +0100 (Tue, 20 Feb 2018) $");
  script_tag(name:"creation_date", value:"2017-09-22 13:09:22 +0530 (Fri, 22 Sep 2017)");
  script_name("Samba Server 'SMB1' Memory Information Leak Vulnerability");

  script_tag(name:"summary", value:"This host is running Samba and is prone
  to memory information leak vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"A server memory information leak bug over SMB1
  if a client can write data to a share. Some SMB1 write requests were not correctly
  range checked to ensure the client had sent enough data to fulfill the write.");

  script_tag(name:"impact", value:"Successful exploitation will allow a client with
  write access to a share can cause server memory contents to be written into a file
  or printer.

  Impact Level: Application");

  script_tag(name:"affected", value:"Samba versions before 4.4.16,
  4.5.0 before 4.5.14, and 4.6.0 before 4.6.8.");

  script_tag(name:"solution", value:"Upgrade to Samba 4.6.8, 4.5.14 and 4.4.16 or later.
  For updates refer to https://www.samba.org");
  
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2017-12163.html");
  script_family("General");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl", "gb_smb_version_detect.nasl");
  script_mandatory_keys("samba/detected");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!sambaPort = get_app_port(cpe:CPE)) exit(0);
if(!sambaVer = get_app_version(cpe:CPE, port:sambaPort)) exit(0);

##Confirm smb1 is enabled on the server
if(!get_kb_item("smb_v1/supported")) exit(0);

##Check for vulnerable versions
if(version_is_less(version:sambaVer, test_version:"4.4.16")){
  fix = "4.4.16";
}
else if(version_in_range(version:sambaVer, test_version:"4.5.0", test_version2:"4.5.13")){
  fix = "4.5.14";
}
else if(version_in_range(version:sambaVer, test_version:"4.6.0", test_version2:"4.6.7")){
  fix = "4.6.8";
}

if(fix) 
{
  report = report_fixed_ver(installed_version:sambaVer, fixed_version:fix);
  security_message(data:report, port:sambaPort);
  exit(0);
}

exit(99);

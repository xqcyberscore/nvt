###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openafs_multiple_vuln_win.nasl 8209 2017-12-21 08:12:18Z cfischer $
#
# OpenAFS Multiple Vulnerabilities (Windows)
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

CPE= "cpe:/a:openafs:openafs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808074");
  script_version("$Revision: 8209 $");
  script_cve_id("CVE-2016-4536", "CVE-2016-2860");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 09:12:18 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2016-06-08 17:01:13 +0530 (Wed, 08 Jun 2016)");
  script_name("OpenAFS Multiple Vulnerabilities (Windows)");

  script_tag(name: "summary" , value: "This host is installed with OpenAFS and
  is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value: "Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value: "Multiple flaws exist due to,
  - An improper validation in the newEntry function in 'ptserver/ptprocs.c'
    script.
  - The client does not properly initialize the AFSStoreStatus,
    AFSStoreVolumeStatus, VldbListByAttributes, and ListAddrByAttributes
    structures.");

  script_tag(name: "impact" , value: "Successful exploitation will allow
  remote attackers to obtain sensitive memory information by leveraging
  access to RPC call traffic and bypass intended access restrictions and
  create arbitrary groups as administrators by leveraging mishandling of
  the creator ID.

  Impact Level: Application.");

  script_tag(name: "affected" , value:"OpenAFS version prior and equal to 1.6.16
  on Windows.");

  script_tag(name: "solution" , value:"Upgrade to OpenAFS version 1.6.17 or later.
  For updates refer to https://www.openafs.org");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name: "URL" , value : "http://www.openafs.org/pages/security/OPENAFS-SA-2016-001.txt");
  script_xref(name: "URL" , value : "http://www.openafs.org/pages/security/OPENAFS-SA-2016-002.txt");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_openafs_detect.nasl");
  script_mandatory_keys("OpenAFS/Win/Installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

## Variable Initialization
afsVer= "";

## Get version
if(!afsVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Check vulnerable versions
if(version_is_less_equal(version:afsVer, test_version:"1.6.16"))
{
  report = report_fixed_ver(installed_version:afsVer, fixed_version: "1.6.17");
  security_message(data:report);
  exit(0);
}

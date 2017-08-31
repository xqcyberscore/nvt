###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_norton_security_cids_dos_vuln.nasl 6506 2017-07-03 10:22:51Z cfischer $
#
# Symantec Norton Security 'CIDS' Driver Denial of Service Vulnerability
# 
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:symantec:norton_security";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808624");
  script_version("$Revision: 6506 $");
  script_cve_id("CVE-2016-5308");
  script_bugtraq_id(91608);
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-03 12:22:51 +0200 (Mon, 03 Jul 2017) $");
  script_tag(name:"creation_date", value:"2016-10-07 13:20:51 +0530 (Fri, 07 Oct 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Symantec Norton Security 'CIDS' Driver Denial of Service Vulnerability");

  script_tag(name: "summary" , value: "This host is installed with Symantec
  Norton Security and is prone to denial of service vulnerability.");

  script_tag(name: "vuldetect" , value: "Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value: "The flaw exists due to the client intrusion
  detection system (CIDS) driver is improperly handling a malformed PE executable
  file.");

  script_tag(name: "impact" , value: "Successful exploitation will allow attackers
  to cause a denial of service (memory corruption and system crash).

  Impact Level: System/Application.");

  script_tag(name: "affected" , value:"Symantec Norton Security CIDS Drivers
  prior to version 15.1.2.");

  script_tag(name: "solution" , value:"Update Symantec Norton Security through
  LiveUpdate.
  For updates refer to https://www.symantec.com");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name: "URL" , value : "https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20160707_01");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_symantec_norton_security_detect.nasl");
  script_mandatory_keys("Symantec/Norton/Security/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

## Variable Initialization
fileVer = "";
nor_ver = 0;
query = "";
usrname = "";
passwd = "";
ver = 0;

##Get version from cpe
if(!nor_ver = get_app_version(cpe:CPE)){
  exit(0);
}

## Get host
host    = get_host_ip();

usrname = get_kb_item("SMB/login");
passwd  = get_kb_item("SMB/password");
domain  = get_kb_item("SMB/domain");
if( domain ) usrname = domain + '\\' + usrname;

if(!host || !usrname || !passwd){
  exit(0);
}

## Get the handle to execute wmi query
handle = wmi_connect(host:host, username:usrname, password:passwd);

if(!handle){
  exit(0);
}

## WMI query to grep the file version
query = 'Select Version from CIM_DataFile Where FileName ='
        + raw_string(0x22) +'IDSvix86' +raw_string(0x22) + ' AND Extension ='
        + raw_string(0x22) +'sys' + raw_string(0x22);

fileVer = wmi_query(wmi_handle:handle, query:query);

if(!fileVer){
  exit(0);
}

foreach ver (split(fileVer))
{
  ver = eregmatch(pattern:"\idsvix86.sys.?([0-9.]+)", string:ver);
  if(ver[1])
  {
    ##Check for vulnerable version of Norton security
    if(version_is_less(version:ver[1], test_version:"15.1.2"))
    {
      report = report_fixed_ver(installed_version:ver[1], fixed_version:"15.1.2");
      security_message(data:report);
      exit(0);
    }
  }
}

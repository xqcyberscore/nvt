###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_microsoft_azure_iot_sdk_spoofing_vuln_sep18_win.nasl 11767 2018-10-05 13:34:39Z cfischer $
#
# Azure IoT SDK Spoofing Vulnerability Sep18 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
##########################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814212");
  script_version("$Revision: 11767 $");
  script_cve_id("CVE-2018-8479");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 15:34:39 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-09-17 14:45:59 +0530 (Mon, 17 Sep 2018)");
  script_name("Azure IoT SDK Spoofing Vulnerability Sep18 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Azure IoT Device
  C SDK library and is prone to a spoofing vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in how the HTTP
  transport library validates certificates.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to impersonate a server used during the provisioning process.");

  script_tag(name:"affected", value:"Azure IoT C SDK");

  script_tag(name:"solution", value:"Upgrade to Azure IoT C SDK 1.2.9 or later.
  For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod", value:"75");

  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8479");
  script_xref(name:"URL", value:"https://github.com/Azure/azure-iot-sdk-c/");
  script_xref(name:"URL", value:"https://github.com/Azure/azure-iot-sdk-c/releases/tag/2018-09-11");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl", "gb_wmi_access.nasl");
  script_mandatory_keys("WMI/access_successful", "SMB/WindowsVersion");

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

infos = kb_smb_wmi_connectinfo();
if( ! infos ) exit( 0 );

handle = wmi_connect( host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"] );
if( ! handle ) exit( 0 );

query1 = 'Select Version from CIM_DataFile Where FileName ='
        + raw_string(0x22) + 'Microsoft.Azure.IoTHub.IoTHubClient' + raw_string(0x22);
fileVer1 = wmi_query( wmi_handle:handle, query:query1);
wmi_close( wmi_handle:handle );
if(!fileVer1) exit( 0 );

foreach ver(split( fileVer1 ))
{
  ver = eregmatch(pattern:".*(M|m)icrosoft.(A|a)zure.(I|i)o(T|t)(H|h)ub.(I|i)o(T|t)(H|h)ub(C|c)lient.([0-9.]+)([-a-zA-Z0-9]+)?", string:ver);
  if(!ver[10]){
    continue;
  }
  version = ver[10];
  filePath = ver[0];

  if(version && version_is_less(version:version, test_version:"1.2.9"))
  {
    report = report_fixed_ver(installed_version:version, fixed_version:"1.2.9", install_path:filePath);
    security_message(data:report);
    exit(0);
  }
}
exit(0);

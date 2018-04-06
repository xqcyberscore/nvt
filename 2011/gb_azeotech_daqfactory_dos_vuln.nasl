###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_azeotech_daqfactory_dos_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# AzeoTech DAQFactory Denial of Service Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow remote attackers to cause a denial of
  service (system reboot or shutdown).
  Impact Level: Application.";
tag_affected = "AzeoTech DAQFactory version prior to 5.85 Build 1842";

tag_insight = "The flaw exists due to error in application, which fails to perform
  authentication for certain signals.";
tag_solution = "Upgrade to the AzeoTech DAQFactory version 5.85 Build 1842 or later
  For updates refer to http://www.azeotech.com/downloads.php";
tag_summary = "This host is installed with AzeoTech DAQFactory and is prone to
  denial of service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802129");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-08-05 09:04:20 +0200 (Fri, 05 Aug 2011)");
  script_cve_id("CVE-2011-2956");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("AzeoTech DAQFactory Denial of Service Vulnerability");
  script_xref(name : "URL" , value : "http://www.us-cert.gov/control_systems/pdf/ICSA-11-122-01.pdf");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\DAQFactoryExpress")){
  exit(0);
}

## Get the installation path from registry
azPath = registry_get_sz(key:"SOFTWARE\DAQFactoryExpress",
                                      item:"Installation Path");
if(azPath != NULL)
{
  azVer = fetch_file_version(sysPath:azPath,
                               file_name:"DAQFactoryExpress.exe");
  if(azVer =! NULL)
  {
    ## Check for version less than 5.85 Build 1842 => 5.85.1842.0
    if(version_is_less(version:azVer, test_version:"5.85.1842.0")){
      security_message(0);
    }
  }
}

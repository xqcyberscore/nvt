###############################################################################
# OpenVAS Vulnerability Test
#
# Intel Security McAfee Security Scan Plus Version Detection (Windows)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810823");
  script_version("2019-10-21T11:05:04+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-10-21 11:05:04 +0000 (Mon, 21 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-03-22 11:19:49 +0530 (Wed, 22 Mar 2017)");
  script_name("Intel Security McAfee Security Scan Plus Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of
  Intel Security McAfee Security Scan Plus.

  The script logs in via SMB, searches for string 'McAfee Security Scan Plus'
  in the registry and reads the version information from registry.");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch)
  exit(0);

if("x86" >< os_arch)
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\McAfee Security Scan\";
else if("x64" >< os_arch)
  key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\McAfee Security Scan\";
else
  exit(0);

app_name = registry_get_sz(key:key, item:"HideDisplayName");
if(!app_name || "McAfee Security Scan Plus" >!< app_name)
  exit(0);

version = "unknown";
location = "unknown";

vers = registry_get_sz(key:key, item:"DisplayVersion");
if(vers)
  version = vers;

path = registry_get_sz(key:key, item:"InstallDirectory");
if(path)
  location = path;

set_kb_item(name:"McAfee/SecurityScanPlus/Win/Ver", value:version);
register_and_report_cpe(app:"Intel Security McAfee Security Scan Plus", ver:version, base:"cpe:/a:intel:mcafee_security_scan_plus:", expr:"^([0-9.]+)", insloc:location, regService:"smb-login", port:0);
exit(0);

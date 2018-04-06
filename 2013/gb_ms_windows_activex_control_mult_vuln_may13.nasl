###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_windows_activex_control_mult_vuln_may13.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Microsoft Windows ActiveX Control Multiple Vulnerabilities (2820197)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_solution = "Apply the patch from below link,
  http://support.microsoft.com/kb/2820197

  Workaround:
  Set the killbit for the following CLSIDs,
  {0d080d7d-28d2-4f86-bfa1-d582e5ce4867},
  {29e9b436-dfac-42f9-b209-bd37bafe9317}.";

tag_impact = "Successful exploitation will let the remote attackers execute arbitrary code,
  and can compromise a vulnerable system.
  Impact Level: System/Application";

tag_affected = "Microsoft Windows 8
  Microsoft Windows Server 2012
  Microsoft Windows XP x32 Edition Service Pack 3 and prior
  Microsoft Windows XP x64 Edition Service Pack 2 and prior
  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
  Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior";
tag_insight = "The flaws are due to errors in the handling of Honeywell Enterprise Buildings
  Integrator, SymmetrE and ComfortPoint Open Manager ActiveX controls.";
tag_summary = "This script will list all the vulnerable activex controls installed
  on the remote windows machine with references and cause.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803701");
  script_version("$Revision: 9353 $");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-05-21 13:06:04 +0530 (Tue, 21 May 2013)");
  script_name("Microsoft Windows ActiveX Control Multiple Vulnerabilities (2820197)");

  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2820197");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/advisory/2820197");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}

include("smb_nt.inc");
include("secpod_activex.inc");

## Confirm windows platform
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

# Check if Kill-Bit is set for ActiveX control
clsids = make_list("{0d080d7d-28d2-4f86-bfa1-d582e5ce4867}",
                   "{29e9b436-dfac-42f9-b209-bd37bafe9317}");

## check for each bit
foreach clsid (clsids)
{
  if(is_killbit_set(clsid:clsid) == 0)
  {
    security_message(0);
    exit(0);
  }
}

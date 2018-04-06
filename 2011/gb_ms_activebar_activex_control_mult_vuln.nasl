###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_activebar_activex_control_mult_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Microsoft Windows ActiveX Control Multiple Vulnerabilities (2562937)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_solution = "Apply the patch from below link,
  http://support.microsoft.com/kb/2562937

  Workaround:
  Set the killbit for the following CLSIDs,
  {B4CB50E4-0309-4906-86EA-10B6641C8392},
  {E4F874A0-56ED-11D0-9C43-00A0C90F29FC},
  {FB7FE605-A832-11D1-88A8-0000E8D220A6}";

tag_impact = "Successful exploitation will let the remote attackers execute arbitrary code,
  and can compromise a vulnerable system.
  Impact Level: System";
tag_affected = "Microsoft Windows 7 Service Pack 1 and prior.
  Microsoft Windows XP Service Pack 3 and prior.
  Microsoft Windows 2003 Service Pack 2 and prior.
  Microsoft Windows Vista Service Pack 2 and prior.
  Microsoft Windows Server 2008 Service Pack 2 and prior.";
tag_insight = "The flaws are due to error in restricting the SetLayoutData method,
  which fails to properly restrict the SetLayoutData method.";
tag_summary = "This script will list all the vulnerable activex controls installed
  on the remote windows machine with references and cause.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801966");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-08-11 06:41:03 +0200 (Thu, 11 Aug 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows ActiveX Control Multiple Vulnerabilities (2562937)");

  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2562937");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/advisory/2562937.mspx");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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
include("secpod_reg.inc");
include("secpod_activex.inc");

## Confirm windows platform
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

# Hotfix check
if(hotfix_missing(name:"2562937") == 0){
  exit(0);
}

# Check if Kill-Bit is set for ActiveX control
clsids = make_list("{B4CB50E4-0309-4906-86EA-10B6641C8392}",
                   "{E4F874A0-56ED-11D0-9C43-00A0C90F29FC}",
                   "{FB7FE605-A832-11D1-88A8-0000E8D220A6}");

## check for each bit
foreach clsid (clsids)
{
  if(is_killbit_set(clsid:clsid) == 0)
  {
    security_message(0);
    exit(0);
  }
}

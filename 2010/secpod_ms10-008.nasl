###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-008.nasl 8724 2018-02-08 15:02:56Z cfischer $
#
# Microsoft Data Analyzer ActiveX Control Vulnerability (978262)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
#  Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-11-22
#        - To confirm Vulnerability on vista, win 2008 and win 7
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,

  http://www.microsoft.com/technet/security/bulletin/ms10-008.mspx

  Workaround:
  Set the killbit for the following CLSIDs,
  {E0ECA9C3-D669-4EF4-8231-00724ED9288F}, {C05A1FBC-1413-11D1-B05F-00805F4945F6},
  {5D80A6D1-B500-47DA-82B8-EB9875F85B4D}, {0CCA191D-13A6-4E29-B746-314DEE697D83},
  {2d8ed06d-3c30-438b-96ae-4d110fdc1fb8}

  http://support.microsoft.com/kb/240797";

tag_impact = "Successful exploitation will let the remote attackers execute arbitrary code
  and can compromise a vulnerable system.

  Impact Level: System.";
tag_affected = "Microsoft Windows 7

  Microsoft Windows 2K  Service Pack 4 and prior

  Microsoft Windows XP  Service Pack 3 and prior

  Microsoft Windows 2K3 Service Pack 2 and prior

  Microsoft Windows Vista Service Pack 1/2 and prior.

  Microsoft Windows Server 2008 Service Pack 1/2 and prior.";
tag_insight = "An unspecified error exists in the Microsoft Data Analyzer ActiveX control
  (max3activex.dll) when used with Internet Explorer. Attackers can execute
  arbitrary code by tricking a user into visiting a specially crafted web page.";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-008.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900229");
  script_version("$Revision: 8724 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-08 16:02:56 +0100 (Thu, 08 Feb 2018) $");
  script_tag(name:"creation_date", value:"2010-02-10 16:06:43 +0100 (Wed, 10 Feb 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0252");
  script_name("Microsoft Data Analyzer ActiveX Control Vulnerability (978262)");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/38503/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0341");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms10-008.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("secpod_activex.inc");

## Check For OS and Service Packs
if(hotfix_check_sp(win2k:5, xp:4, win2003:3, winVista:3, win2008:3, win7:1) <= 0){
  exit(0);
}

## MS10-008 Hotfix check
if(hotfix_missing(name:"978262") == 0){
  exit(0);
}

## CLSID List
clsids = make_list(
  "{E0ECA9C3-D669-4EF4-8231-00724ED9288F}", "{C05A1FBC-1413-11D1-B05F-00805F4945F6}",
  "{5D80A6D1-B500-47DA-82B8-EB9875F85B4D}", "{0CCA191D-13A6-4E29-B746-314DEE697D83}",
  "{2d8ed06d-3c30-438b-96ae-4d110fdc1fb8}");

foreach clsid (clsids)
{
  ## Check if Kill-Bit is set for ActiveX control
  if(is_killbit_set(clsid:clsid) == 0)
  {
    security_message(0);
    exit(0);
  }
}

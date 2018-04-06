###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_win_fraudulent_digital_cert_spoofing_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Fraudulent Digital Certificates Spoofing Vulnerability (2607712)
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

tag_impact = "Successful exploitation will allow remote attackers to spoof content, perform
  phishing attacks or perform man-in-the-middle attacks against all Web browser
  users including users of Internet Explorer.
  Impact Level: System";
tag_affected = "Windows 7 Service Pack 1 and prior
  Windows XP Service Pack 3 and prior
  Windows Vista Service Pack 2 and prior
  Windows Server 2003 Service Pack 2 and prior
  Windows Server 2008 Service Pack 2 and prior";
tag_insight = "The flaw is due to an error when handling the fraudulent digital
  certificates issued by Comodo and it is not properly validating its
  identity.";
tag_solution = "Apply the Patch from below link,
  For updates refer to http://support.microsoft.com/kb/2607712";
tag_summary = "The host is installed with Microsoft Windows operating system and
  is prone to spoofing vulnerability.

  This NVT has been superseded by KB2641690 Which is addressed in NVT
  gb_ms_fraudulent_digital_cert_spoofing_vuln.nasl (OID:1.3.6.1.4.1.25623.1.0.802403).";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801975");
  script_version("$Revision: 9351 $");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-09-09 17:36:48 +0200 (Fri, 09 Sep 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Fraudulent Digital Certificates Spoofing Vulnerability (2607712)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2607712");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/advisory/2607712.mspx");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

exit(66); ## This NVT is deprecated asit is superseded by KB2641690
          ## Which is addressed in gb_ms_fraudulent_digital_cert_spoofing_vuln.nasl

include("smb_nt.inc");
include("secpod_reg.inc");

## Confirm Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

## Check Hotfix 2607712
if(!(hotfix_missing(name:"2607712") == 0)){
  security_message(0);
}

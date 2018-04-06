###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_dell_webcam_activex_mult_bof_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Dell Webcam 'crazytalk4.ocx' ActiveX Multiple BOF Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow remote attackers to execute
arbitrary code in the context of the application using the ActiveX control.

Impact Level: System/Application";

tag_affected = "Dell Webcam";

tag_insight = "The flaws are due to boundary error when processing user-supplied
input.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Dell Webcam and is prone to multiple
buffer overflow vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903013");
  script_version("$Revision: 9352 $");
  script_bugtraq_id(52571, 52560);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-03-29 14:38:14 +0530 (Thu, 29 Mar 2012)");
  script_name("Dell Webcam 'crazytalk4.ocx' ActiveX Multiple BOF Vulnerabilities");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/52571/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/52560/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18621/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_activex.inc");

## Confirm Windows OS
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Check if Kill-Bit is set
if(is_killbit_set(clsid:"{13149882-F480-4F6B-8C6A-0764F75B99ED}") == 0){
  security_message(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_outlook_express_dos_vuln.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# Microsoft Outlook Express Malformed MIME Message DoS Vulnerability
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation could result in application to crash.
  Impact Level: Application";
tag_affected = "Microsoft Outlook Express 6.x to 6.00.2900.5512";
tag_insight = "Flaw is due to improper handling of multipart/mixed e-mail messages
  with many MIME parts and e-mail messages with many Content-type: message/rfc822
  headers in MimeOleClearDirtyTree function of InetComm.dll file.";
tag_solution = "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided
  anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by
  another one.
  For updates refer to http://office.microsoft.com/en-us/outlook/default.aspx";
tag_summary = "The host is installed with Microsoft Outlook Express and is prone
  to denial of service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800083");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-12-18 14:07:48 +0100 (Thu, 18 Dec 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-5424");
  script_bugtraq_id(32702);
  script_name("Microsoft Outlook Express Malformed MIME Message DoS Vulnerability");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/499038");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/499045");
  script_xref(name : "URL" , value : "http://mime.recurity.com/cgi-bin/twiki/view/Main/AttackIntro");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(!dllPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:dllPath + "\inetcomm.dll");

# Get version for inetcomm.dll file
dllVer = GetVer(file:file, share:share);
if(!dllVer){
  exit(0);
}

# Version match from 6.0 to 6.00.2900.5512
if(version_in_range(version:dllVer, test_version:"6.0",
                    test_version2:"6.00.2900.5512")){
  security_message(0);
}

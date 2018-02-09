###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_fraudulent_digital_certificates_sooping_vuln.nasl 8724 2018-02-08 15:02:56Z cfischer $
#
# Microsoft Windows Fraudulent Digital Certificates Spoofing Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_summary = "This NVT has been replaced by NVT gb_ms_windows_fraudulent_digital_cert_spoofing_vuln.nasl
  (OID:1.3.6.1.4.1.25623.1.0.801953).

  The host is installed with Microsoft Windows operating system and is prone to
  Spoofing vulnerability.";

tag_impact = "Successful exploitation will allow remote attackers to spoof content, perform
  phishing attacks, or perform man-in-the-middle attacks against all Web browser
  users including users of Internet Explorer.

  Impact Level: System.";
tag_affected = "Microsoft Windows 7 Service Pack 1 and prior.

  Microsoft Windows XP Service Pack 3 and prior.

  Microsoft Windows 2K3 Service Pack 2 and prior.

  Microsoft Windows Vista Service Pack 2 and prior.

  Microsoft Windows Server 2008 Service Pack 2 and prior.";
tag_insight = "The flaw is caused by an error related to the use of several revoked and
  fraudulent SSL certificates for public web sites, which could allow attackers
  to decrypt SSL traffic sent to legitimate web sites by manipulating the DNS
  servers and using the fraudulent certificates.";
tag_solution = "Apply the patch from below link,

  For updates refer to http://support.microsoft.com/kb/2524375";

if(description)
{
  script_id(902403);
  script_version("$Revision: 8724 $");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"$Date: 2018-02-08 16:02:56 +0100 (Thu, 08 Feb 2018) $");
  script_tag(name:"creation_date", value:"2011-04-01 15:39:52 +0200 (Fri, 01 Apr 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Microsoft Windows Fraudulent Digital Certificates Spoofing Vulnerability");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/advisory/2524375.mspx");
  script_xref(name : "URL" , value : "http://forums.cnet.com/7723-6132_102-521672.html?messageId=5105699");
  script_xref(name : "URL" , value : "http://vulnerabilityteam.blogspot.com/2011/03/fraudulent-ssl-certificates.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Windows");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


exit(66); ## This NVT is deprecated as addressed in
          ## gb_ms_windows_fraudulent_digital_cert_spoofing_vuln.nasl.

include("smb_nt.inc");
include("secpod_reg.inc");

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

## Check for the patch
if(!hotfix_missing(name:"2524375") == 0){
  security_message(0);
}

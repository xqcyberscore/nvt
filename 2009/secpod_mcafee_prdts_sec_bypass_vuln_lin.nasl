###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mcafee_prdts_sec_bypass_vuln_lin.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# McAfee Products Security Bypass Vulnerability (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
##############################################################################

tag_impact = "Successful exploitation will allow attackers to bypass the anti-virus
  scanning and distribute files containing malicious code that the antivirus
  application will fail to detect.
  Impact Level: System/Application";
tag_affected = "McAfee VirusScan Command Line
  McAfee VirusScan Enterprise Linux
  McAfee software that uses DAT files prior to 5600 on Linux";
tag_insight = "Error in AV Engine fails to handle specially crafted packets via,
  - an invalid Headflags and Packsize fields in a malformed RAR archive.
  - an invalid Filelength field in a malformed ZIP archive.";
tag_solution = "Updates are available through DAT files 5600 or later
  http://www.mcafee.com/apps/downloads/security_updates/dat.asp";
tag_summary = "This host is installed with McAfee products and are prone to
  Security Bypass vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900359");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-05-26 15:05:11 +0200 (Tue, 26 May 2009)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1348");
  script_bugtraq_id(34780);
  script_name("McAfee Products Security Bypass Vulnerability (Linux)");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("gather-package-list.nasl");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34949");
  script_xref(name : "URL" , value : "http://blog.zoller.lu/2009/04/case-for-av-bypassesevasions.html");
  script_xref(name : "URL" , value : "http://blog.zoller.lu/2009/04/mcafee-multiple-bypassesevasions-ziprar.html");
  script_xref(name : "URL" , value : "https://kc.mcafee.com/corporate/index?page=content&id=SB10001&actp=LIST_RECENT");
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

datPath = find_bin(prog_name:"uvscan_secure", sock:sock);
foreach path (datPath)
{
  ver = ssh_cmd(cmd:string(chomp(path)+ " --version"), socket:sock, timeout:60);

  datVer = eregmatch(pattern:"Virus data file v([0-9]{4})",
                     string:strstr(ver, "Virus data file v"));
  if(datVer[1] != NULL)
  {
    if(version_is_less(version:datVer[1], test_version:"5600"))
    {
      security_message(0);
      ssh_close_connection();
      exit(0);
    }
  }
}
ssh_close_connection();

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_noip_dns_bof_vuln.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# No-IP DUC Remote code execution vulnerability
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

tag_impact = "Successful attack could result in remote DNS servers to execute arbitrary
  code via a crafted DNS response.
  Impact Level: Application";
tag_affected = "No-IP DUC 2.1.7 and prior on Linux";
tag_insight = "The flaw is due to DNS poisoning in the function GetNextLine which fails
  to do length check.";
tag_solution = "Upgrade to latest version of No-IP DUC,
  http://www.no-ip.com/downloads.php";
tag_summary = "This host has No-IP DUC installed and is prone to remote code
  execution vulnerability.";


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800084");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-12-18 14:07:48 +0100 (Thu, 18 Dec 2008)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5297");
  script_name("No-IP DUC Remote code execution vulnerability");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7151");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2008/11/21/15");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("gather-package-list.nasl");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

binFile = find_bin(prog_name:"noip2", sock:sock);
foreach binaryFile (binFile)
{
  if( chomp(binaryFile) == "" ) continue;
  noipVer = get_bin_version(full_prog_name:chomp(binaryFile),
                            version_argv:"-h",
                            ver_pattern:"Version Linux-([0-9.]+)", sock:sock);
  if(noipVer[1] != NULL)
  {
    if(version_is_less_equal(version:noipVer[1], test_version:"2.1.7")){
      security_message(0);
    }
    ssh_close_connection();
    exit(0);
  }
}
ssh_close_connection();

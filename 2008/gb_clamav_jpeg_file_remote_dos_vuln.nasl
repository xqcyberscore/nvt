###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_clamav_jpeg_file_remote_dos_vuln.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# ClamAV Remote Denial of Service Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation will cause remote attackers to crash the daemon via
  a specially crafted JPEG file.
  Impact Level: Application";
tag_affected = "ClamAV before 0.94.2 on Linux";
tag_insight = "The application fails to validate user input passed to cli_check_jpeg_exploit,
  jpeg_check_photoshop, and jpeg_check_photoshop_8bim functions in special.c file.";
tag_solution = "Upgrade to ClamAV 0.94.2
  http://www.clamav.net/";
tag_summary = "This host has ClamAV installed, and is prone to denial of service
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800079");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-12-12 16:11:26 +0100 (Fri, 12 Dec 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-5314");
  script_bugtraq_id(32555);
  script_name("ClamAV Remote Denial of Service Vulnerability");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2008/12/01/8");
  script_xref(name : "URL" , value : "http://lurker.clamav.net/message/20081126.150241.55b1e092.en.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
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

getPath = find_bin(prog_name:"clamscan", sock:sock);
foreach binaryFile (getPath)
{
  if( chomp(binaryFile) == "" ) continue;
  avVer = get_bin_version(full_prog_name:chomp(binaryFile), version_argv:"-V",
                          ver_pattern:"ClamAV ([0-9.]+)", sock:sock);
  if(avVer[1] != NULL)
  {
    # Check for < 0.94.2 version of ClamAV
    if(version_is_less(version:avVer[1], test_version:"0.94.2")){
      security_message(0);
    }
    ssh_close_connection(); # If version is found and not vulnerable, close and exit
    exit(0);
  }
}
ssh_close_connection();

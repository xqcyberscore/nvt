###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_chm2pdf_insec_tmp_file_crtn_vuln.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# chm2pdf Insecure Temporary File Creation or DoS Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

tag_solution = "Upgrade to higher version or Apply patches from,
  http://bugs.debian.org/cgi-bin/bugreport.cgi?msg=20;filename=chm2pdf_nmu.diff;att=1;bug=501959

  ******
  NOTE: Please ignore this warning if already patch is applied.
  ******";

tag_impact = "Successful exploitation will allow local users to delete arbitrary files
  via symlink attack or corrupt sensitive files, which may also result in a
  denial of service.
  Impact Level: Application";
tag_affected = "chm2pdf version prior to 0.9.1 on Debian";
tag_insight = "The vulnerability is due to following,
  - error in .chm file in /tmp/chm2pdf/orig and /tmp/chm2pdf/work temporary
    directories.
  - uses temporary files in directories with fixed names.";
tag_summary = "This host is installed with chm2pdf and is prone to Insecure
  Temporary File Creation or Denial of Service Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800316");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-12-12 16:11:26 +0100 (Fri, 12 Dec 2008)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5298", "CVE-2008-5299");
  script_bugtraq_id(31735);
  script_name("chm2pdf Insecure Temporary File Creation or DoS Vulnerability");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/32257/");
  script_xref(name : "URL" , value : "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=501959");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2008/12/01/5");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("gather-package-list.nasl");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

# Exit if other than Debian platform
if(ssh_cmd(socket:sock, cmd:"cat /etc/debian_version") !~ "^[0-9.]+"){
  exit(0);
}

binPaths = find_file(file_name:"chm2pdf", file_path:"/", useregex:TRUE,
                     regexpar:"$", sock:sock);
foreach c2pBin (binPaths)
{
  c2pVer = get_bin_version(full_prog_name:chomp(c2pBin), version_argv:"--version",
                           ver_pattern:"version ([0-9.]+)", sock:sock);
  if(c2pVer[1] != NULL)
  {
    if(version_is_less(version:c2pVer[1], test_version:"0.9.1")){
      security_message(0);
    }
    ssh_close_connection();
    exit(0);
  }
}
ssh_close_connection();

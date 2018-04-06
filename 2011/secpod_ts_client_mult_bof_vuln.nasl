###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ts_client_mult_bof_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Terminal Server Client RDP File Processing BOF Vulnerabilities
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

tag_impact = "Successful exploitation allows attackers to execute arbitrary
code, crash the application or deny service to legitimate users.

Impact Level: Application.";

tag_affected = "Terminal Server Client version 0.150";

tag_insight = "Multiple flaws are due to a boundary error in the
'tsc_launch_remote()' function, when processing a 'hostname', 'username',
'password' and 'domain' parameters.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Terminal Server Client and is prone
to multiple buffer overflow vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902297");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-02-28 11:12:07 +0100 (Mon, 28 Feb 2011)");
  script_cve_id("CVE-2011-0900", "CVE-2011-0901");
  script_bugtraq_id(46099);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Terminal Server Client RDP File Processing BOF Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43120");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/65100");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/16095/");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Buffer overflow");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

## Check the file path
paths = find_file(file_name:"NEWS.gz",file_path:"/doc/tsclient/",
                  useregex:TRUE, regexpar:"$", sock:sock);
## check for each path
foreach binName (paths)
{
  ## get the version by reading file using zcat command
  tscVer = get_bin_version(full_prog_name:"zcat", version_argv:binName,
                ver_pattern:"v.([0-9]\.[0-9]+)" ,sock:sock);
  
  ##  check version
  if(tscVer[1] != NULL)
  {
    ## Check tsclient version equal to 0.150
    if(version_is_equal(version:tscVer[1], test_version:"0.150"))
    {
      security_message(0);
      close(sock);
      exit(0);
    }
  }
}

## Close the socket
close(sock);
ssh_close_connection();

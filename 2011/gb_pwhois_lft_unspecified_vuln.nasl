###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pwhois_lft_unspecified_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# pWhois Layer Four Traceroute (LFT) Unspecified Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
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

tag_impact = "Successful exploitation will allow attacker to gain privileges.";
tag_affected = "pWhois Layer Four Traceroute (LFT) 3.x before 3.3";
tag_insight = "An unspecified vulnerability exists in application, which allows local users
  to gain privileges via a crafted command line.";
tag_solution = "Upgrade Layer Four Traceroute to 3.3 or later,
  For updates refer to http://pwhois.org/lft/";
tag_summary = "This host is installed with Whois Layer Four Traceroute (LFT) and
  is prone to unspecified vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801915");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-04-13 15:50:09 +0200 (Wed, 13 Apr 2011)");
  script_cve_id("CVE-2011-1652");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("pWhois Layer Four Traceroute (LFT) Unspecified Vulnerability");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/946652");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

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

## get the possible paths
paths = find_bin(prog_name:"lft", sock:sock);
foreach bin (paths)
{
  ## check for each path
  lftVer = get_bin_version(full_prog_name:chomp(bin), sock:sock, version_argv:"-v",
                           ver_pattern:"version ([0-9.]+)");

  if(lftVer[1] != NULL)
  {
    # Grep for version 3.x to 3.2 or prior
    if(version_in_range(version:lftVer[1], test_version:"3.0", test_version2:"3.2"))
    {
      security_message(0);
      close(sock);
      exit(0);
    }
    ssh_close_connection();
  }
}
close(sock);
ssh_close_connection();

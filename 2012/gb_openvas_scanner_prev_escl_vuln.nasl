###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openvas_scanner_prev_escl_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# OpenVAS Scanner Symlink Attack Local Privilege Escalation Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_insight = "The flaw is due to the application passing a predictable temporary
  filename to the '-r' parameter of the ovaldi application, which can be
  exploited to overwrite arbitrary files via symlink attacks.

  NOTE: This vulnerability exists when ovaldi support enabled.";

tag_impact = "Successful exploitation allows local user on a client or server system can
  gain access to the administrator or root account thus taking full control
  of the system.
  Impact Level: Application.";
tag_affected = "OpenVAS Project OpenVAS Scanner 3.2.4";
tag_solution = "Upgrade to OpenVAS Scanner 4 or later,
  For updates refer to http://www.openvas.org/software.html";
tag_summary = "This host is installed with OpenVAS Scanner and is prone to
  privilege escalation vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801979");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2011-3351");
  script_bugtraq_id(49460);
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-01-10 17:29:46 +0530 (Tue, 10 Jan 2012)");
  script_name("OpenVAS Scanner Symlink Attack Local Privilege Escalation Vulnerability");
  script_xref(name : "URL" , value : "http://seclists.org/oss-sec/2011/q3/432");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/45836");
  script_xref(name : "URL" , value : "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=641327");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "insight" , value : tag_insight);
  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

foreach command (make_list("openvasd"))
{
  ## Find the command path
  openvasName = find_file(file_name:command, file_path:"/", useregex:TRUE,
                         regexpar:"$", sock:sock);

  ## Check for each path
  foreach binaryName (openvasName)
  {
    openvasVer = get_bin_version(full_prog_name:chomp(binaryName),
             version_argv:"--version", ver_pattern:"OpenVAS.(Scanner)?.?([0-9.]+)",
             sock:sock);

    ## check for the version
    if(openvasVer[2])
    {
      if(version_is_less_equal(version:openvasVer[2], test_version:"3.2.4"))
      {
        security_message(0);
        close(sock);
        exit(0);
      }
    }
  }
}
close(sock);

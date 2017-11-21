###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_sys_web_serv_heap_bof_vuln_lin.nasl 7823 2017-11-20 08:54:04Z cfischer $
#
# Sun Java System Web Server Multiple Heap-based Buffer Overflow Vulnerabilities (Linux)
#
# Authors:
# Veerendra G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation lets the attackers to cause the application to crash
  or execute arbitrary code on the system by sending an overly long request in
  an 'Authorization: Digest' header.
  Impact Level: System/Application";
tag_affected = "Sun Java System Web Server version 7.0 update 7 on Linux.";
tag_insight = "An error exists in in webservd and admin server that can be exploited to
  overflow a buffer and execute arbitrary code on the system or cause the
  server to crash via a long string in an 'Authorization: Digest' HTTP
  header.";
tag_solution = "Upgrade to Sun Java System Web Server version 7.0 update 8 or later.
For updates refer to http://www.sun.com/";
tag_summary = "This host has Sun Java Web Server running which is prone to
  multiple Heap-based Buffer Overflow Vulnerabilities.";

if(description)
{
  script_id(800160);
  script_version("$Revision: 7823 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-20 09:54:04 +0100 (Mon, 20 Nov 2017) $");
  script_tag(name:"creation_date", value:"2010-02-02 07:26:26 +0100 (Tue, 02 Feb 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-0387");
  script_bugtraq_id(37896);
  script_name("Sun Java System Web Server Multiple Heap-based Buffer Overflow Vulnerabilities (Linux)");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/55792");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/Jan/1023488.html");
  script_xref(name : "URL" , value : "http://intevydis.blogspot.com/2010/01/sun-java-system-web-server-70u7-digest.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_sun_java_sys_web_serv_detect.nasl", "gather-package-list.nasl");
  script_mandatory_keys("java_system_web_server/installed", "login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");

## Check for Sun Java System Web Server 7.0
if( get_kb_item("Sun/JavaSysWebServ/Ver") != "7.0"){
  exit(0);
}

jswsSock = ssh_login_or_reuse_connection();
if(!jswsSock){
  exit(0);
}

## Find path of the given file
paths = find_file(file_name:"webservd", file_path:"/", useregex:TRUE,
                  regexpar:"$", sock:jswsSock);

## Iterate over all paths
foreach sjswsBin (paths)
{
  ## Extract version from the file
  sjswsVer = get_bin_version(full_prog_name:chomp(sjswsBin), sock:jswsSock,
                        version_argv:"-v",
                        ver_pattern:"Sun (ONE |Java System )Web Server " +
                                    "([0-9.]+)(SP|U)?([0-9]+)?([^0-9.]|$)");
  ## Construct proper file version
  if(sjswsVer[2] != NULL)
  {
     if(sjswsVer[4] != NULL)
       sjswsVer = sjswsVer[2] + "." + sjswsVer[4];
     else
       sjswsVer = sjswsVer[2];

    ## Check for Web Server version 7.0 Update 7
    if(version_is_equal(version:sjswsVer, test_version:"7.0.7"))
    {
      sjswsPort = get_kb_item("Sun/JavaSysWebServ/Port");
      security_message(sjswsPort);
      ssh_close_connection();
      exit(0);
    }
  }
}

ssh_close_connection();

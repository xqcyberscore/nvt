###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_sys_web_serv_heap_bof_vuln_lin.nasl 11119 2018-08-26 14:11:51Z cfischer $
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800160");
  script_version("$Revision: 11119 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-26 16:11:51 +0200 (Sun, 26 Aug 2018) $");
  script_tag(name:"creation_date", value:"2010-02-02 07:26:26 +0100 (Tue, 02 Feb 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-0387");
  script_bugtraq_id(37896);
  script_name("Sun Java System Web Server Multiple Heap-based Buffer Overflow Vulnerabilities (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/55792");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Jan/1023488.html");
  script_xref(name:"URL", value:"http://intevydis.blogspot.com/2010/01/sun-java-system-web-server-70u7-digest.html");

  script_tag(name:"impact", value:"Successful exploitation lets the attackers to cause the application to crash
  or execute arbitrary code on the system by sending an overly long request in
  an 'Authorization: Digest' header.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Sun Java System Web Server version 7.0 update 7 on Linux.");

  script_tag(name:"insight", value:"An error exists in in webservd and admin server that can be exploited to
  overflow a buffer and execute arbitrary code on the system or cause the
  server to crash via a long string in an 'Authorization: Digest' HTTP
  header.");

  script_tag(name:"solution", value:"Upgrade to Sun Java System Web Server version 7.0 update 8 or later.
  For updates refer to http://www.sun.com/");

  script_tag(name:"summary", value:"This host has Sun Java Web Server running which is prone to
  multiple Heap-based Buffer Overflow Vulnerabilities.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

jswsSock = ssh_login_or_reuse_connection();
if( ! jswsSock ) exit( 0 );

paths = find_file( file_name:"webservd", file_path:"/", useregex:TRUE, regexpar:"$", sock:jswsSock );

foreach sjswsBin( paths ) {

  sjswsBin = chomp( sjswsBin );
  if( ! sjswsBin ) continue;

  sjswsVer = get_bin_version( full_prog_name:sjswsBin, sock:jswsSock, version_argv:"-v", ver_pattern:"Sun (ONE |Java System )Web Server ([0-9.]+)(SP|U)?([0-9]+)?([^0-9.]|$)" );
  if( sjswsVer[2] ) {
    if( ! isnull( sjswsVer[4] ) ) {
      sjswsVer = sjswsVer[2] + "." + sjswsVer[4];
    } else {
      sjswsVer = sjswsVer[2];
    }

    if( version_is_equal( version:sjswsVer, test_version:"7.0.7" ) ) {
      report = report_fixed_ver( installed_version:sjswsVer, fixed_version:"7.0.8", install_path:sjswsBin );
      security_message( port:0, data:report );
      ssh_close_connection();
      exit( 0 );
    }
  }
}

ssh_close_connection();
exit( 99 );
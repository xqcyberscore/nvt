###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_sys_web_serv_bof_vuln_lin.nasl 11116 2018-08-26 13:08:29Z cfischer $
#
# Sun Java System Web Server Buffer Overflow Vulnerability (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801147");
  script_version("$Revision: 11116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-26 15:08:29 +0200 (Sun, 26 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-11-12 15:21:24 +0100 (Thu, 12 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Sun Java System Web Server Buffer Overflow Vulnerability (Linux)");
  script_cve_id("CVE-2009-3878");
  script_bugtraq_id(36813);
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"http://intevydis.com/vd-list.shtml");
  script_xref(name:"URL", value:"http://www.intevydis.com/blog/?p=79");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37115");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3024");

  script_tag(name:"impact", value:"Successful exploitation lets the attackers to execute arbitrary
  code in the context of an affected system.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Sun Java System Web Server version 7.0 update 6 and prior on
  Linux.");

  script_tag(name:"insight", value:"An unspecified error that can be exploited to cause a buffer
  overflow.");

  script_tag(name:"solution", value:"Upgrade to version 7.0 update 7 or later,
  For updates refer to http://www.sun.com");

  script_tag(name:"summary", value:"This host has Sun Java Web Server running which is prone to
  Buffer Overflow vulnerability.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

jswsSock = ssh_login_or_reuse_connection();
if( ! jswsSock ) exit( 0 );

paths = find_file( file_name:"webservd", file_path:"/", useregex:TRUE, regexpar:"$", sock:jswsSock );
foreach jswsBin( paths ) {

  jswsBin = chomp( jswsBin );
  if( ! jswsBin ) continue;

  ver = get_bin_version( full_prog_name:jswsBin, sock:jswsSock, version_argv:"-v", ver_pattern:"Sun (ONE |Java System )Web Server ([0-9.]+)(SP|U)?([0-9]+)?([^0-9.]|$)" );
  if( ! isnull( ver[2] ) ) {
    if( ! isnull( ver[4] ) )
      ver = ver[2] + "." + ver[4];
    else
      ver = ver[2];

    if( version_is_less_equal( version:ver, test_version:"7.0.6" ) ) {
      report = report_fixed_ver( installed_version:ver, fixed_version:"7.0.7", install_path:jswsBin );
      security_message( port:0, data:report );
      ssh_close_connection();
      exit( 0 );
    }
  }
}

ssh_close_connection();
exit( 99 );
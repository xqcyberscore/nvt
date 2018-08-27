###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_sys_web_serv_mult_vuln_lin.nasl 11120 2018-08-26 14:29:50Z cfischer $
#
# Sun Java System Web Server Multiple Vulnerabilities (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.800156");
  script_version("$Revision: 11120 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-26 16:29:50 +0200 (Sun, 26 Aug 2018) $");
  script_tag(name:"creation_date", value:"2010-02-04 12:53:38 +0100 (Thu, 04 Feb 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0272", "CVE-2010-0273", "CVE-2010-0360", "CVE-2010-0361",
                "CVE-2010-0388", "CVE-2010-0389");
  script_bugtraq_id(37910);
  script_name("Sun Java System Web Server Multiple Vulnerabilities (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"http://intevydis.com/sjws_demo.html");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/55812");
  script_xref(name:"URL", value:"http://intevydis.blogspot.com/2010/01/sun-java-system-web-server-70-admin.html");
  script_xref(name:"URL", value:"http://intevydis.blogspot.com/2010/01/sun-java-system-web-server-70-webdav.html");
  script_xref(name:"URL", value:"http://intevydis.blogspot.com/2010/01/sun-java-system-web-server-70u7-trace.html");
  script_xref(name:"URL", value:"http://intevydis.blogspot.com/2010/01/sun-java-system-web-server-70u7-webdav.html");

  script_tag(name:"impact", value:"Successful exploitation lets the attackers to discover process memory
  locations or execute arbitrary code in the context of an affected system
  or cause the application to crash via a long URI in an HTTP OPTIONS request.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Sun Java System Web Server version 7.0 update 6 on Linux.
  Sun Java System Web Server version 7.0 update 7 on Linux.");

  script_tag(name:"insight", value:"- An error exists in WebDAV implementation in webservd and can be exploited
  to cause Stack-based buffer overflow via long URI in an HTTP OPTIONS request.

  - An unspecified error that can be exploited to cause a heap-based buffer
  overflow which allows remote attackers to discover process memory
  locations and execute arbitrary code by sending a process memory address
  via crafted data.

  - Format string vulnerability in the WebDAV implementation in webservd that
  can be exploited to cause denial of service via format string specifiers
  in the encoding attribute of the XML declaration in a PROPFIND request.

  - An unspecified error in admin server that can be exploited to cause
  denial of service via an HTTP request that lacks a method token.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host has Sun Java Web Server running which is prone to
  Multiple Vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"executable_version");

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
  if( ! isnull( sjswsVer[2] ) ) {
    if( ! isnull( sjswsVer[4] ) ) {
      sjswsVer = sjswsVer[2] + "." + sjswsVer[4];
    } else {
      sjswsVer = sjswsVer[2];
    }

    if( version_is_equal( version:sjswsVer, test_version:"7.0.6" ) ||
        version_is_equal( version:sjswsVer, test_version:"7.0.7" ) ) {
      report = report_fixed_ver( installed_version:sjswsVer, fixed_version:"WillNotFix", install_path:sjswsBin );
      security_message( port:0, data:report );
      ssh_close_connection();
      exit( 0 );
    }
  }
}

ssh_close_connection();
exit( 99 );
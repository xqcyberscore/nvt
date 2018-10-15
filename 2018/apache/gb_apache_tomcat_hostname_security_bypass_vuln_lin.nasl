###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_tomcat_hostname_security_bypass_vuln_lin.nasl 11897 2018-10-15 05:26:22Z cfischer $
#
# Apache Tomcat 'Hostname Verification' Security Bypass Vulnerability (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813743");
  script_version("$Revision: 11897 $");
  script_cve_id("CVE-2018-8034");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-15 07:26:22 +0200 (Mon, 15 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-08-03 16:58:57 +0530 (Fri, 03 Aug 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Apache Tomcat 'Hostname Verification' Security Bypass Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is installed with Apache Tomcat
  and is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to a missing host name
  verification when using TLS with the WebSocket client.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to bypass certain security restrictions and perform unauthorized actions.

  Impact Level: Application");

  script_tag(name:"affected", value:"Apache Tomcat versions 9.0.0.M1 to 9.0.9,
  8.5.0 to 8.5.31, 8.0.0.RC1 to 8.0.52 and 7.0.35 to 7.0.88 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Apache Tomcat version 9.0.10 or
  8.5.32 or 8.0.53 or 7.0.90 or later. For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://mail-archives.us.apache.org/mod_mbox/www-announce/201807.mbox/%3C20180722091057.GA70283@minotaur.apache.org%3E");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.10");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.0.53");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.32");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.90");
  script_xref(name:"URL", value:"http://tomcat.apache.org");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ApacheTomcat/installed","Host/runs_unixoide");
  script_require_ports("Services/www", 8080);
  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if(!tomPort = get_app_port(cpe:CPE)){
  exit(0);
}

infos = get_app_version_and_location(cpe:CPE, port:tomPort, exit_no_version:TRUE);
appVer = infos['version'];
path = infos['location'];

if(appVer =~ "8\.5")
{
  if(version_in_range(version:appVer, test_version: "8.5.0", test_version2: "8.5.31")){
    fix = "8.5.32";
  }
}
else if(appVer =~ "7\.0")
{
  if(version_in_range(version:appVer, test_version: "7.0.35", test_version2: "7.0.88")){
    fix = "7.0.90";
  }
}
else if(appVer =~ "8\.0")
{
  if((revcomp(a:appVer, b: "8.0.0.RC1") >= 0) && (revcomp(a:appVer, b: "8.0.53") < 0)){
    fix = "8.0.53";
  }
}
else if(appVer =~ "9\.0")
{
  if((revcomp(a:appVer, b: "9.0.0.M1") >= 0) && (revcomp(a:appVer, b: "9.0.10") < 0)){
    fix = "9.0.10";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:appVer, fixed_version:fix, install_path:path);
  security_message(port:tomPort, data: report);
  exit(0);
}
exit(99);

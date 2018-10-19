###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_tomcat_http2_security_bypass_vuln_lin.nasl 11962 2018-10-18 10:51:32Z mmartin $
#
# Apache Tomcat HTTP2 Security Bypass Vulnerability (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.811299");
  script_version("$Revision: 11962 $");
  script_cve_id("CVE-2017-7675");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:51:32 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-11 15:59:34 +0530 (Fri, 11 Aug 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Apache Tomcat HTTP2 Security Bypass Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is installed with Apache Tomcat
  and is prone to security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in HTTP2
  implementation which bypasses a number of security checks.");

  script_tag(name:"impact", value:"Successful exploitation will allows remote
  attackers to bypass certain security restrictions using an specially crafted
  URL.");

  script_tag(name:"affected", value:"Apache Tomcat versions 9.0.0.M1 to 9.0.0.M21,
  Apache Tomcat versions 8.5.0 to 8.5.15 on Linux.");

  script_tag(name:"solution", value:"Upgrade to version 9.0.0.M22 or 8.5.16 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bz.apache.org/bugzilla/show_bug.cgi?id=61120");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.16");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.0.M22");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ApacheTomcat/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 8080);
  exit(0);
}


include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if(!tomPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!appVer = get_app_version(cpe:CPE, port:tomPort)){
  exit(0);
}

if(appVer =~ "^(8\.5)")
{
  if(revcomp(a: appVer, b: "8.5.16") < 0){
    fix = "8.5.16";
  }
}
else if(appVer =~ "^(9\.)")
{
  if(revcomp(a: appVer, b: "9.0.0.M22") < 0){
    fix = "9.0.0-M22";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:appVer, fixed_version:fix);
  security_message(data:report, port:tomPort);
  exit(0);
}
exit(0);

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_tomcat_http2_dos_vuln_win.nasl 11923 2018-10-16 10:38:56Z mmartin $
#
# Apache Tomcat 'HTTP2' Denial of Service Vulnerability (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.811297");
  script_version("$Revision: 11923 $");
  script_cve_id("CVE-2016-6817");
  script_bugtraq_id(94462);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-16 12:38:56 +0200 (Tue, 16 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-11 13:49:43 +0530 (Fri, 11 Aug 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache Tomcat 'HTTP2' Denial of Service Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with Apache Tomcat
  and is prone to denial-of-service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in  HTTP2 header
  parser in Apache Tomcat which enters an infinite loop if a header was received
  that was larger than the available buffer.");

  script_tag(name:"impact", value:"Successful exploitation will allows remote
  attackers to conduct a denial-of-service condition.");

  script_tag(name:"affected", value:"Apache Tomcat versions 9.0.0.M1 to 9.0.0.M11,
  Apache Tomcat versions 8.5.0 to 8.5.6 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Apache Tomcat version
  9.0.0.M13 or 8.5.8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.8");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.0.M13");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ApacheTomcat/installed", "Host/runs_windows");
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

if(appVer =~ "^(8\.5\.)")
{
  if(revcomp(a: appVer, b: "8.5.8") < 0){
    fix = "8.5.8";
  }
}

else if(appVer =~ "^(9\.)")
{
  if(revcomp(a: appVer, b: "9.0.0.M13") < 0){
    fix = "9.0.0.M13";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:appVer, fixed_version:fix);
  security_message(data:report, port:tomPort);
  exit(0);
}
exit(0);

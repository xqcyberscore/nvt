###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webmin_unspecified_mult_xss_vuln_jul17_lin.nasl 7543 2017-10-24 11:02:02Z cfischer $
#
# Webmin Multiple Unspecified XSS Vulnerabilities July17 (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:webmin:webmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811504");
  script_version("$Revision: 7543 $");
  script_cve_id("CVE-2017-2106");
  script_bugtraq_id(96227);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-24 13:02:02 +0200 (Tue, 24 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-07-11 15:47:13 +0530 (Tue, 11 Jul 2017)");
  script_name("Webmin Multiple Unspecified XSS Vulnerabilities July17 (Linux)");

  script_tag(name:"summary", value:"This host is running Webmin and is prone 
  to multiple unspecified cross site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws exist due to issues in 
  outputting error messages into a HTML page and the function to edit the 
  database.");

  script_tag(name:"impact", value:"Successful exploitation will lead an attacker
  to inject arbitrary web script or HTML.

  Impact Level: Application");

  script_tag(name:"affected", value:"Webmin versions before 1.830");

  script_tag(name:"solution", value:"Upgrade to Webmin version 1.830 or later.
  For updates refer to http://www.webmin.com");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN34207650/index.html");
  script_xref(name:"URL", value:"http://www.webmin.com/changes.html");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("webmin.nasl", "os_detection.nasl");
  script_mandatory_keys("webmin/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 10000, 20000);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

#Variable initialize
wmport = "";
wmver = "";
report = "";

## Get Port
if(!wmport = get_app_port(cpe:CPE)){
 exit(0);
}

## Get the version
if(!wmver = get_app_version(cpe:CPE, port:wmport)){
 exit(0);
}

if(version_is_less(version:wmver, test_version:"1.830"))
{
  report = report_fixed_ver(installed_version:wmver, fixed_version:"1.830");
  security_message(data:report, port:wmport);
  exit(0);
}
exit(0);

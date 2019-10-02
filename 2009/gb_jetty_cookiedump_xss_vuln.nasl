###############################################################################
# OpenVAS Vulnerability Test
#
# Jetty 'CookieDump.java' Cross-Site Scripting Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800954");
  script_version("2019-09-26T06:54:12+0000");
  script_tag(name:"last_modification", value:"2019-09-26 06:54:12 +0000 (Thu, 26 Sep 2019)");
  script_tag(name:"creation_date", value:"2009-10-20 14:26:56 +0200 (Tue, 20 Oct 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2009-3579");

  script_name("Jetty 'CookieDump.java' Cross-Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://www.coresecurity.com/content/jetty-persistent-xss");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/507013/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_jetty_detect.nasl");
  script_mandatory_keys("jetty/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code
  and conduct XSS attacks via a direct GET request to cookie/.");

  script_tag(name:"affected", value:"Jetty version 6.1.19 and 6.1.20.");

  script_tag(name:"insight", value:"The user supplied data passed into the 'Value' parameter in the Sample
  Cookies aka 'CookieDump.java' application is not adequately sanitised before being returned to the user.");

  script_tag(name:"solution", value:"Upgrade to version 6.1.21 or 7.0.0 or later.");

  script_tag(name:"summary", value:"This host is running Jetty WebServer and is prone to Cross-Site Scripting
  vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

vers = infos['version'];
path = infos['location'];

if (version_is_equal(version: vers, test_version: "6.1.19")||
    version_is_equal(version: vers, test_version: "6.1.20")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "6.1.21", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

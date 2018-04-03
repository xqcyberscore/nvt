###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webmin_xss_vuln02_mar18_lin.nasl 9269 2018-03-30 05:36:10Z santu $
#
# Webmin Cross-Site Scripting Vulnerability-02 Mar18 (Linux)
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:webmin:webmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812841");
  script_version("$Revision: 9269 $");
  script_cve_id("CVE-2011-1937");
  script_bugtraq_id(47558);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-03-30 07:36:10 +0200 (Fri, 30 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-03-29 11:07:00 +0530 (Thu, 29 Mar 2018)");
  script_name("Webmin Cross-Site Scripting Vulnerability-02 Mar18 (Linux)");

  script_tag(name:"summary", value:"The host is installed with Webmin and is
  prone to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of the detect NVT and check if the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists because Webmin fails to 
  properly filter HTML code from user-supplied input in the user's full name 
  before displaying the input.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute an arbitrary script in victim's Web browser within the security
  context of the hosting Web site.

  Impact Level: Application");

  script_tag(name:"affected", value:"Webmin versions before 1.550 on Linux.");

  script_tag(name:"solution", value:"Upgrade to version 1.550 or later,
  For updates refer to http://www.webmin.com");
  
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"https://securitytracker.com/id?1025438");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("webmin.nasl", "os_detection.nasl");
  script_mandatory_keys("Host/runs_unixoide", "webmin/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!wport = get_app_port(cpe:CPE)){
  exit(0);
}

infos = get_app_version_and_location(cpe:CPE, port:wport, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];

if(version_is_less( version: vers, test_version:"1.550") )
{
 report = report_fixed_ver(installed_version:vers, fixed_version:"1.550" , install_path:path);
 security_message(port:wport, data:report);
 exit(0);
}
exit(0);

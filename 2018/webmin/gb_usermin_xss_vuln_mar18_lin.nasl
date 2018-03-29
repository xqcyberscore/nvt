###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_usermin_xss_vuln_mar18_lin.nasl 9267 2018-03-29 13:08:08Z santu $
#
# Usermin Cross-Site Scripting Vulnerability Mar18 (Linux)
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

CPE = "cpe:/a:webmin:usermin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812840");
  script_version("$Revision: 9267 $");
  script_cve_id("CVE-2009-4568");
  script_bugtraq_id(37259);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-03-29 15:08:08 +0200 (Thu, 29 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-03-29 11:06:29 +0530 (Thu, 29 Mar 2018)");
  script_name("Usermin Cross-Site Scripting Vulnerability Mar18 (Linux)");

  script_tag(name:"summary", value:"The host is installed with Usermin and is
  prone to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of the detect NVT and check if the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists because Usermin fails to
  sanitize user input for unspecified vectors.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute an arbitrary script on victim's Web browser within the security
  context of the hosting Web site.

  Impact Level: Application");

  script_tag(name:"affected", value:"Usermin versions before 1.430 on Linux.");

  script_tag(name:"solution", value:"Upgrade to version 1.430 or later. 
  For updates refer to www.webmin.com");
  
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-4568");
  script_xref(name:"URL", value:"http://www.webmin.com/security.html");
 
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("webmin.nasl", "os_detection.nasl");
  script_mandatory_keys("Host/runs_unixoide", "usermin/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!wport = get_app_port(cpe: CPE))
  exit(0);

infos = get_app_version_and_location(cpe:CPE, port:wport, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];

if(version_is_less(version: vers, test_version:"1.430"))
{
 report = report_fixed_ver(installed_version:vers, fixed_version:"1.430" , install_path:path);
 security_message(port:wport, data:report);
 exit(0);
}

exit(0);

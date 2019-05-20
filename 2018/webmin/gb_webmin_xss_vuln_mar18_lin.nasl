###############################################################################
# OpenVAS Vulnerability Test
#
# Webmin Cross-Site Scripting Vulnerability Mar18 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.812843");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2014-0339");
  script_bugtraq_id(66248);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-03-29 11:07:15 +0530 (Thu, 29 Mar 2018)");
  script_name("Webmin Cross-Site Scripting Vulnerability Mar18 (Linux)");

  script_tag(name:"summary", value:"The host is installed with Webmin and is
  prone to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists because Webmin fails to
  adequately validate user-supplied input in the id parameter of view.cgi
  script.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute a script on victim's Web browser within the security context of
  the hosting Web site.");

  script_tag(name:"affected", value:"Webmin versions before 1.680 on Linux.");

  script_tag(name:"solution", value:"Upgrade to version 1.680 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Mar/274");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("webmin.nasl", "os_detection.nasl");
  script_mandatory_keys("webmin/installed", "Host/runs_unixoide");
  script_xref(name:"URL", value:"http://www.webmin.com");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!wport = get_app_port(cpe: CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:wport, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"1.680"))
{
 report = report_fixed_ver(installed_version:vers, fixed_version:"1.680" , install_path:path);
 security_message(port:wport, data:report);
 exit(0);
}
exit(0);

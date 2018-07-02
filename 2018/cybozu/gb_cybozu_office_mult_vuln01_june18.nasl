###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cybozu_office_mult_vuln01_june18.nasl 10371 2018-06-29 13:27:39Z santu $
#
# Cybozu Office Multiple Vulnerabilities-01 June18
# 
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:cybozu:office";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813617");
  script_version("$Revision: 10371 $");
  script_cve_id("CVE-2018-0526", "CVE-2018-0527", "CVE-2018-0528", "CVE-2018-0529");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-06-29 15:27:39 +0200 (Fri, 29 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-27 11:07:13 +0530 (Wed, 27 Jun 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Cybozu Office Multiple Vulnerabilities-01 June18");

  script_tag(name: "summary" , value: "This host is installed with Cybozu Office
  and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value: "Get the installed version with the help
  of the detect NVT and check if the version is vulnerable or not.");

  script_tag(name: "insight" , value: "Multiple flaws are due to,

  - An error in the application 'Message' when viewing an external image.

  - An input validation error in 'E-mail Details Screen' of the application 'E-mail'.

  - A browse restriction bypass error in the application 'Scheduler'.

  - An error in the application 'Message' due to a flaw in processing of an 
    attached file.");

  script_tag(name: "impact" , value: "Successful exploitation will allow attackers
  to disclose sensitive information, execute arbitrary script, bypass security
  restrictions and cause denial of service condition.

  Impact Level: System/Application.");

  script_tag(name: "affected" , value:"Cybozu Office versions 10.0.0 to 10.7.0.");

  script_tag(name: "solution" , value:"Upgrade to Cybozu Office version 10.8.0 or
  later. For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name: "URL" , value : "http://jvn.jp/en/jp/JVN51737843/index.html");
  script_xref(name: "URL" , value : "https://office-users.cybozu.co.jp");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("secpod_cybozu_products_detect.nasl");
  script_mandatory_keys("CybozuOffice/Installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!Port = get_app_port(cpe:CPE)){
  exit(0);
}

infos = get_app_version_and_location(cpe:CPE, port:Port, exit_no_version:TRUE );
cybVer = infos['version'];
path = infos['location'];

if(cybVer =~ "10\.")
{
  if(version_is_less_equal(version:cybVer, test_version:"10.7.0"))
  {
    report = report_fixed_ver(installed_version:cybVer, fixed_version:"10.8.0", install_path:path);
    security_message(data:report, port:Port);
    exit(0);
  }
}

exit(0);

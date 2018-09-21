###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_open_audit_attribute_fun_xss_vuln.nasl 11499 2018-09-20 10:38:00Z ckuersteiner $
#
# Open-AudIT Community 'Attributes' Functionality Cross Site Scripting Vulnerability
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

CPE = "cpe:/a:opmantek:open-audit";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813675");
  script_version("$Revision: 11499 $");
  script_cve_id("CVE-2018-11124");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-20 12:38:00 +0200 (Thu, 20 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-07-16 12:35:38 +0530 (Mon, 16 Jul 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("Open-AudIT Community 'Attributes' Functionality Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"The host is installed with Open-AudIT
  and is prone to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an insufficient sanitization
  of attribute name of an Attribute.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML.");

  script_tag(name:"affected", value:"Open-AudIT Community versions prior to 2.2.2");

  script_tag(name:"solution", value:"Upgrade to Open-AudIT Community version 2.2.2
  or later. For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://docs.google.com/document/d/1dJP1CQupHGXjsMWthgPGepOkcnxYA4mDfdjOE46nrhM");
  script_xref(name:"URL", value:"https://opmantek.com");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_open_audit_detect.nasl");
  script_mandatory_keys("open-audit/detected");
  script_require_ports("Services/www", 80, 443, 8080);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:version, test_version:"2.2.2")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"2.2.2");
  security_message(data:report, port:port);
  exit(0);
}

exit(0);

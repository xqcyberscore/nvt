###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_webLogic_server_cpujul2017-3236622_03.nasl 11982 2018-10-19 08:49:21Z mmartin $
#
# Oracle WebLogic Server 'Web Container' Component Unspecified Vulnerability (cpujul2017-3236622)
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

CPE = "cpe:/a:bea:weblogic_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811246");
  script_version("$Revision: 11982 $");
  script_cve_id("CVE-2017-10123");
  script_bugtraq_id(99650);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 10:49:21 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-19 13:58:23 +0530 (Wed, 19 Jul 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Oracle WebLogic Server 'Web Container' Component Unspecified Vulnerability (cpujul2017-3236622)");

  script_tag(name:"summary", value:"The host is running Oracle WebLogic Server
  and is prone to some unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to unspecified error
  in the 'Web Container' component of the application.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to have an impact on confidentiality.");

  script_tag(name:"affected", value:"Oracle WebLogic Server versions 12.1.3.0");

  script_tag(name:"solution", value:"Apply update");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("oracle_webLogic_server_detect.nasl");
  script_mandatory_keys("OracleWebLogicServer/installed");
  script_require_ports("Services/www", 7001);
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!webPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!webVer = get_app_version(cpe:CPE, port:webPort)){
  exit(0);
}

if( webVer == "12.1.3.0")
{
  report = report_fixed_ver(installed_version:webVer, fixed_version:"Apply the appropriate patch");
  security_message(data:report, port:webPort);
  exit(0);
}
exit(0);

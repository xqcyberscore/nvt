###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_spip_plugin_id_param_mult_xss_vuln.nasl 11961 2018-10-18 10:49:40Z asteins $
#
# SPIP 'plugin' and 'id' Parameters Multiple Cross-Site Scripting Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:spip:spip";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809766");
  script_version("$Revision: 11961 $");
  script_cve_id("CVE-2016-9998", "CVE-2016-9997");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:49:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-12-19 14:42:01 +0530 (Mon, 19 Dec 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("SPIP 'plugin' and 'id' Parameters Multiple Cross-Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with SPIP
  and is prone to multiple cross-site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an insufficient
  validation of input passed via 'id' parameter to '/ecrire/exec/puce_statut.php'
  script and 'plugin' parameter to '/ecrire/exec/info_plugin.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser session within
  the trust relationship between their browser and the server.");

  script_tag(name:"affected", value:"SPIP version 3.1.x through 3.1.3");

  script_tag(name:"solution", value:"Update to 3.1.4.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://core.spip.net/projects/spip/repository/revisions/23288");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_spip_detect.nasl");
  script_mandatory_keys("spip/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://www.spip.net");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!sp_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!sp_Ver = get_app_version(cpe:CPE, port:sp_port)){
  exit(0);
}

if(version_in_range(version:sp_Ver, test_version:"3.1.0", test_version2:"3.1.3"))
{
  report = report_fixed_ver(installed_version:sp_Ver, fixed_version:"3.1.4");
  security_message(port:sp_port, data:report);
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zabbix_info_disclosure_may18.nasl 9913 2018-05-22 01:05:37Z ckuersteiner $
#
# Zabbix Server Information Disclosure Vulnerability May18
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

CPE = "cpe:/a:zabbix:zabbix";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812869");
  script_version("$Revision: 9913 $");
  script_cve_id("CVE-2017-2826");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-05-22 03:05:37 +0200 (Tue, 22 May 2018) $");
  script_tag(name:"creation_date", value:"2018-05-02 16:58:57 +0530 (Wed, 02 May 2018)");
  script_name("Zabbix Server Information Disclosure Vulnerability May18");

  script_tag(name:"summary", value:"The host is installed with Zabbix server and
  is prone to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of the detect NVT and check if the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to Zabbix server unable
  to sanitize against a specially crafted iConfig proxy request.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to make requests from an active Zabbix proxy and cause the Zabbix server to
  send the configuration information of any Zabbix proxy

  Impact Level: Application");

  script_tag(name:"affected", value:"Zabbix server version 2.4.X");

  script_tag(name:"solution", value:"No known solution is available as of 01st May, 2018. Information regarding
this issue will be updated once solution details are available.");
  
  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2017-0327");
  script_xref(name:"URL", value:"http://www.zabbix.com");  
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("zabbix_web_detect.nasl");
  script_mandatory_keys("Zabbix/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!zport = get_app_port(cpe: CPE))
  exit(0);

infos = get_app_version_and_location(cpe:CPE, port:zport, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];

if(vers=~"^2\.4\.")
{
 report = report_fixed_ver(installed_version:vers, fixed_version:"NoneAvailable", install_path:path);
 security_message(port:zport, data:report);
 exit(0);
}

exit(0);


###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_http_server_mod_cluster_dos_vuln_win.nasl 9895 2018-05-18 04:24:05Z ckuersteiner $
#
# Apache HTTP Server 'mod_cluster' Denial of Service Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812579");
  script_version("$Revision: 9895 $");
  script_cve_id("CVE-2016-8612");
  script_bugtraq_id(94939);
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-05-18 06:24:05 +0200 (Fri, 18 May 2018) $");
  script_tag(name:"creation_date", value:"2018-03-21 11:34:53 +0530 (Wed, 21 Mar 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache HTTP Server 'mod_cluster' Denial of Service Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is running Apache HTTP Server
  and is prone to denial of service vulnerability");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to an error in protocol
  parsing logic of mod_cluster load balancer Apache HTTP Server modules that
  allows attacker to cause a Segmentation Fault in the serving httpd process.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service condition.

  Impact Level: Application");

  script_tag(name:"affected", value:"Apache HTTP Server version 2.4.23 on Windows.");

  script_tag(name:"solution", value:"See the vendor advisory for a solution.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=1387605");
  script_xref(name : "URL" , value : "https://tools.cisco.com/security/center/viewAlert.x?alertId=57169");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("secpod_apache_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/installed", "Host/runs_windows");
  script_require_ports("Services/www", 80);

  # This is a Redhat vulnerability (mod_cluster) an not in Apache itself
  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}


exit(66);

include("host_details.inc");
include("version_func.inc");

if(!httpd_port = get_app_port(cpe:CPE)){
  exit(0);
}

infos = get_app_version_and_location(cpe:CPE, port:httpd_port, exit_no_version:TRUE);
httpd_ver = infos['version'];
path = infos['location'];

if(httpd_ver == "2.4.23")
{
  report = report_fixed_ver(installed_version:httpd_ver, fixed_version:"NoneAvailable", install_path:path);
  security_message(data:report, port:httpd_port);
  exit(0);
}

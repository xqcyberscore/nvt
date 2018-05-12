###############################################################################
# OpenVAS Vulnerability Test
# $Id: EZsiteForum.nasl 9782 2018-05-09 13:46:05Z cfischer $
# Description: EZsite Forum Discloses Passwords to Remote Users
#
# Authors:
# deepquest <deepquest@code511.com>
#
#  Date: 4 sep , 2003  7:07:39  AM
#  From: cyber_talon <cyber_talon@hotmail.com>
#  Subject: EZsite Forum Discloses Passwords to Remote Users
#
# Copyright:
# Copyright (C) 2003 deepquest
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

tag_summary = "The remote host is running EZsite Forum.

It is reported that this software stores usernames and passwords in
plaintext form in the 'Database/EZsiteForum.mdb' file. A remote user
can reportedly download this database.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11833");
 script_version("$Revision: 9782 $");
 script_tag(name:"last_modification", value:"$Date: 2018-05-09 15:46:05 +0200 (Wed, 09 May 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("EZsite Forum Discloses Passwords to Remote Users");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_active");
 script_tag(name:"solution_type", value:"WillNotFix");
 script_copyright("This script is Copyright (C) 2003 deepquest");
 script_family("Web application abuses");
 script_dependencies("secpod_ms_iis_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("IIS/installed");

 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if( ! get_kb_item("IIS/" + port + "/Ver" ) ) exit( 0 );

foreach dir( make_list_unique( "/forum", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string(dir, "/Database/EZsiteForum.mdb");

  if(http_vuln_check(port:port, url:url,pattern:"Standard Jet DB")) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
